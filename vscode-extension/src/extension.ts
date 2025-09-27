import * as vscode from 'vscode';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import archiver from 'archiver';
import axios from 'axios';
import FormData from 'form-data';

const execAsync = promisify(exec);

async function createZipFromFolder(folderPath: string): Promise<string> {
  const tempZipPath = path.join(os.tmpdir(), `upload-${Date.now()}.zip`);
  await new Promise<void>((resolve, reject) => {
    const output = fs.createWriteStream(tempZipPath);
    const archive = archiver('zip', { zlib: { level: 9 } });
    output.on('close', () => resolve());
    output.on('error', reject);
    archive.on('error', reject);
    archive.pipe(output);
    archive.directory(folderPath, false);
    archive.finalize().catch(reject);
  });
  return tempZipPath;
}

async function createPythonOnlyZipFromFolder(folderPath: string): Promise<string> {
  const tempDir = path.join(os.tmpdir(), `python-source-${Date.now()}`);
  const sourceDir = path.join(tempDir, 'source');
  
  fs.mkdirSync(sourceDir, { recursive: true });

  try {
    // Copy only Python files from the workspace folder
    const fileCount = await copyPythonFilesRecursively(folderPath, sourceDir);
    
    if (fileCount === 0) {
      throw new Error('No Python files found in the workspace folder');
    }

    vscode.window.showInformationMessage(`Found ${fileCount} Python files. Creating zip...`);

    // Create ZIP file
    const zipPath = path.join(os.tmpdir(), `upload-${Date.now()}.zip`);
    await new Promise<void>((resolve, reject) => {
      const output = fs.createWriteStream(zipPath);
      const archive = archiver('zip', { zlib: { level: 9 } });
      
      output.on('close', resolve);
      output.on('error', reject);
      archive.on('error', reject);
      
      archive.pipe(output);
      archive.directory(tempDir, false);
      archive.finalize().catch(reject);
    });

    fs.rmSync(tempDir, { recursive: true, force: true });
    return zipPath;
  } catch (error) {
    fs.rmSync(tempDir, { recursive: true, force: true });
    throw error;
  }
}

async function uploadZipToPythonServer(zipPath: string, analysisType: 'integrated' | 'vulnerability' | 'malicious' = 'integrated'): Promise<{session_id: string, dashboard_url: string}> {
  const form = new FormData();
  form.append('file', fs.createReadStream(zipPath), path.basename(zipPath));
  form.append('analysis_type', analysisType);
  
  const response = await axios.post('http://127.0.0.1:8000/upload', form, {
    headers: form.getHeaders(),
    maxContentLength: Infinity,
    maxBodyLength: Infinity,
    timeout: 30000 // 30초 타임아웃
  });
  return response.data;
}

async function getPythonSitePackagesPath(): Promise<string> {
  try {
    const { stdout } = await execAsync('python -c "import site; print(site.getsitepackages()[0])"');
    let detectedPath = stdout.trim();
    
    // Fix common path issue where Python returns base directory instead of site-packages
    if (!detectedPath.includes('site-packages')) {
      const sitePackagesPath = path.join(detectedPath, 'Lib', 'site-packages');
      if (fs.existsSync(sitePackagesPath)) {
        return sitePackagesPath;
      }
    }
    
    return detectedPath;
  } catch (error) {
    // Fallback to common Windows path
    const fallbackPath = path.join(process.env.USERPROFILE || '', 'AppData', 'Local', 'Programs', 'Python', 'Python313', 'Lib', 'site-packages');
    if (fs.existsSync(fallbackPath)) {
      return fallbackPath;
    }
    throw new Error('Could not find site-packages directory');
  }
}

async function getInstalledPackages(): Promise<string[]> {
  try {
    const { stdout } = await execAsync('pip list --format=freeze');
    return stdout.split('\n')
      .filter(line => line.trim() && line.includes('=='))
      .map(line => line.split('==')[0]);
  } catch (error) {
    vscode.window.showErrorMessage(`Failed to get installed packages: ${error}`);
    return [];
  }
}

async function getInstalledPackagesFromTable(): Promise<{ name: string; version: string }[]> {
  try {
    const { stdout } = await execAsync('pip list');
    const lines = stdout.split('\n').map(l => l.trim()).filter(Boolean);
    const results: { name: string; version: string }[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^Package\s+Version/i.test(line)) {
        // Skip header and optional separator
        i += 1;
        continue;
      }
      if (/^-{2,}\s+-{2,}/.test(line)) {
        // separator row like "------- -------"
        continue;
      }
      const parts = line.split(/\s+/);
      if (parts.length >= 2) {
        const name = parts[0];
        const version = parts[1];
        if (name && version) {
          results.push({ name, version });
        }
      }
    }
    return results;
  } catch (error) {
    vscode.window.showErrorMessage(`Failed to parse pip list: ${error}`);
    return [];
  }
}

async function getPipShowInfo(packageName: string): Promise<string> {
  try {
    const { stdout } = await execAsync(`pip show ${packageName}`);
    return stdout;
  } catch (error) {
    return `Error getting info for ${packageName}: ${error}`;
  }
}

async function extractPythonPackageSources(sitePackagesPath: string, packageName: string, outputDir: string): Promise<number> {
  const packagePath = path.join(sitePackagesPath, packageName);
  
  if (!fs.existsSync(packagePath)) {
    return 0;
  }

  const packageOutputDir = path.join(outputDir, packageName);
  fs.mkdirSync(packageOutputDir, { recursive: true });

  return await copyPythonFilesRecursively(packagePath, packageOutputDir);
}

async function copyPythonFilesRecursively(sourceDir: string, destDir: string): Promise<number> {
  let fileCount = 0;
  
  try {
    const items = fs.readdirSync(sourceDir);

    for (const item of items) {
      const sourcePath = path.join(sourceDir, item);
      const destPath = path.join(destDir, item);
      
      // Skip metadata directories
      if (item.includes('.dist-info') || item.includes('.egg-info') || item === '__pycache__') {
        continue;
      }

      const stat = fs.statSync(sourcePath);
      
      if (stat.isDirectory()) {
        fs.mkdirSync(destPath, { recursive: true });
        fileCount += await copyPythonFilesRecursively(sourcePath, destPath);
      } else if (stat.isFile() && item.endsWith('.py')) {
        fs.copyFileSync(sourcePath, destPath);
        fileCount++;
      }
    }
  } catch (error: any) {
    if (error.code === 'EACCES' || error.code === 'EPERM') {
      throw new Error('Permission denied. Please run VS Code as administrator.');
    }
    throw error;
  }

  return fileCount;
}

async function createPythonPackagesZip(): Promise<string> {
  const tempDir = path.join(os.tmpdir(), `python-packages-${Date.now()}`);
  const sourceDir = path.join(tempDir, 'source');
  const metadataDir = path.join(tempDir, 'metadata');
  
  fs.mkdirSync(sourceDir, { recursive: true });
  fs.mkdirSync(metadataDir, { recursive: true });

  try {
    const sitePackagesPath = await getPythonSitePackagesPath();
    const packages = await getInstalledPackages();
    
    vscode.window.showInformationMessage(`Found ${packages.length} packages. Extracting sources...`);

    // Extract sources and create metadata for each package
    for (const packageName of packages) {
      const fileCount = await extractPythonPackageSources(sitePackagesPath, packageName, sourceDir);
      const pipShowInfo = await getPipShowInfo(packageName);
      fs.writeFileSync(path.join(metadataDir, `${packageName}.txt`), pipShowInfo);
      
      if (fileCount > 0) {
        console.log(`Extracted ${fileCount} files from ${packageName}`);
      }
    }

    // versions.txt based on default `pip list` table output (write at root)
    const tablePkgs = await getInstalledPackagesFromTable();
    if (tablePkgs.length > 0) {
      const versionsLines = tablePkgs.map(p => `${p.name} ${p.version}`);
      fs.writeFileSync(path.join(tempDir, 'versions.txt'), versionsLines.join('\n'));
    }

    // Create ZIP file
    const zipPath = path.join(os.tmpdir(), `python-packages-${Date.now()}.zip`);
    await new Promise<void>((resolve, reject) => {
      const output = fs.createWriteStream(zipPath);
      const archive = archiver('zip', { zlib: { level: 9 } });
      
      output.on('close', resolve);
      output.on('error', reject);
      archive.on('error', reject);
      
      archive.pipe(output);
      archive.directory(tempDir, false);
      archive.finalize().catch(reject);
    });

    fs.rmSync(tempDir, { recursive: true, force: true });
    return zipPath;
  } catch (error) {
    fs.rmSync(tempDir, { recursive: true, force: true });
    throw error;
  }
}

export function activate(context: vscode.ExtensionContext) {
  // Helper function to handle analysis with specific type
  async function performAnalysis(
    createZipFunction: () => Promise<string>, 
    analysisType: 'integrated' | 'vulnerability' | 'malicious',
    analysisName: string
  ) {
    try {
      vscode.window.showInformationMessage(`${analysisName} 분석을 시작합니다...`);
      
      const zipPath = await createZipFunction();
      const result = await uploadZipToPythonServer(zipPath, analysisType);
      
      const analysisTypeText = {
        'integrated': '통합',
        'vulnerability': '취약점',
        'malicious': '악성'
      }[analysisType];
      
      const queuePosition = result.queue_position || 0;
      const statusMessage = queuePosition > 0 
        ? `${analysisTypeText} 분석이 대기열에 추가되었습니다! (대기 순서: ${queuePosition}번째)`
        : `${analysisTypeText} 분석이 시작되었습니다!`;
      
      vscode.window.showInformationMessage(
        `${statusMessage} 세션 ID: ${result.session_id}`,
        '대시보드 열기'
      ).then(selection => {
        if (selection === '대시보드 열기') {
          vscode.env.openExternal(vscode.Uri.parse(result.dashboard_url));
        }
      });
      
      fs.unlinkSync(zipPath);
    } catch (error: any) {
      const message = error?.message ?? String(error);
      if (message.includes('Permission denied')) {
        vscode.window.showErrorMessage('권한이 부족합니다. VS Code를 관리자 권한으로 실행해주세요.');
      } else if (message.includes('timeout')) {
        vscode.window.showErrorMessage('서버 연결 시간이 초과되었습니다. 서버가 실행 중인지 확인해주세요.');
      } else if (message.includes('ECONNREFUSED')) {
        vscode.window.showErrorMessage('서버에 연결할 수 없습니다. 서버가 실행 중인지 확인해주세요.');
      } else {
        vscode.window.showErrorMessage(`${analysisName} 분석 실패: ${message}`);
      }
    }
  }

  // 1. 통합 분석 - 프로젝트
  const disposable1 = vscode.commands.registerCommand('vscode-extension.uploadZipToLocal', async () => {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!workspaceFolder) {
      vscode.window.showErrorMessage('워크스페이스 폴더가 없습니다. 폴더를 열고 다시 시도하세요.');
      return;
    }
    
    await performAnalysis(
      () => createPythonOnlyZipFromFolder(workspaceFolder),
      'integrated',
      '프로젝트 통합'
    );
  });

  // 2. 통합 분석 - 설치된 패키지
  const disposable2 = vscode.commands.registerCommand('vscode-extension.extractPythonPackages', async () => {
    await performAnalysis(
      () => createPythonPackagesZip(),
      'integrated',
      '설치된 패키지 통합'
    );
  });

  // 3. 취약점 분석 - 프로젝트
  const disposable3 = vscode.commands.registerCommand('vscode-extension.analyzeProjectVulnerability', async () => {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!workspaceFolder) {
      vscode.window.showErrorMessage('워크스페이스 폴더가 없습니다. 폴더를 열고 다시 시도하세요.');
      return;
    }
    
    await performAnalysis(
      () => createPythonOnlyZipFromFolder(workspaceFolder),
      'vulnerability',
      '프로젝트 취약점'
    );
  });

  // 4. 악성 분석 - 프로젝트
  const disposable4 = vscode.commands.registerCommand('vscode-extension.analyzeProjectMalicious', async () => {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!workspaceFolder) {
      vscode.window.showErrorMessage('워크스페이스 폴더가 없습니다. 폴더를 열고 다시 시도하세요.');
      return;
    }
    
    await performAnalysis(
      () => createPythonOnlyZipFromFolder(workspaceFolder),
      'malicious',
      '프로젝트 악성'
    );
  });

  // 5. 취약점 분석 - 설치된 패키지
  const disposable5 = vscode.commands.registerCommand('vscode-extension.analyzePackagesVulnerability', async () => {
    await performAnalysis(
      () => createPythonPackagesZip(),
      'vulnerability',
      '설치된 패키지 취약점'
    );
  });

  // 6. 악성 분석 - 설치된 패키지
  const disposable6 = vscode.commands.registerCommand('vscode-extension.analyzePackagesMalicious', async () => {
    await performAnalysis(
      () => createPythonPackagesZip(),
      'malicious',
      '설치된 패키지 악성'
    );
  });

  context.subscriptions.push(disposable1, disposable2, disposable3, disposable4, disposable5, disposable6);
}

export function deactivate() {}



