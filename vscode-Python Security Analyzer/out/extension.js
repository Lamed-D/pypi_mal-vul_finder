"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const child_process_1 = require("child_process");
const util_1 = require("util");
const archiver_1 = __importDefault(require("archiver"));
const axios_1 = __importDefault(require("axios"));
const form_data_1 = __importDefault(require("form-data"));
const execAsync = (0, util_1.promisify)(child_process_1.exec);
async function createZipFromFolder(folderPath) {
    const tempZipPath = path.join(os.tmpdir(), `upload-${Date.now()}.zip`);
    await new Promise((resolve, reject) => {
        const output = fs.createWriteStream(tempZipPath);
        const archive = (0, archiver_1.default)('zip', { zlib: { level: 9 } });
        output.on('close', () => resolve());
        output.on('error', reject);
        archive.on('error', reject);
        archive.pipe(output);
        archive.directory(folderPath, false);
        archive.finalize().catch(reject);
    });
    return tempZipPath;
}
async function createPythonOnlyZipFromFolder(folderPath) {
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
        await new Promise((resolve, reject) => {
            const output = fs.createWriteStream(zipPath);
            const archive = (0, archiver_1.default)('zip', { zlib: { level: 9 } });
            output.on('close', resolve);
            output.on('error', reject);
            archive.on('error', reject);
            archive.pipe(output);
            archive.directory(tempDir, false);
            archive.finalize().catch(reject);
        });
        fs.rmSync(tempDir, { recursive: true, force: true });
        return zipPath;
    }
    catch (error) {
        fs.rmSync(tempDir, { recursive: true, force: true });
        throw error;
    }
}
async function uploadZipToPythonServer(zipPath, analysisType = 'integrated') {
    const form = new form_data_1.default();
    form.append('file', fs.createReadStream(zipPath), path.basename(zipPath));
    // 새로운 API 엔드포인트에 맞게 URL 설정
    let apiUrl = 'http://127.0.0.1:8000/api/v1/upload/lstm'; // 기본: both (취약점 + 악성코드)
    if (analysisType === 'vulnerability') {
        apiUrl = 'http://127.0.0.1:8000/api/v1/upload/lstm/vul';
    }
    else if (analysisType === 'malicious') {
        apiUrl = 'http://127.0.0.1:8000/api/v1/upload/lstm/mal';
    }
    const response = await axios_1.default.post(apiUrl, form, {
        headers: form.getHeaders(),
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
        timeout: 30000 // 30초 타임아웃
    });
    // 응답에서 dashboard_url 생성
    const result = response.data;
    result.dashboard_url = `http://127.0.0.1:8000/session/${result.session_id}`;
    return result;
}
async function getPythonSitePackagesPath() {
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
    }
    catch (error) {
        // Fallback to common Windows path
        const fallbackPath = path.join(process.env.USERPROFILE || '', 'AppData', 'Local', 'Programs', 'Python', 'Python313', 'Lib', 'site-packages');
        if (fs.existsSync(fallbackPath)) {
            return fallbackPath;
        }
        throw new Error('Could not find site-packages directory');
    }
}
async function getInstalledPackages() {
    try {
        const { stdout } = await execAsync('pip list --format=freeze');
        return stdout.split('\n')
            .filter(line => line.trim() && line.includes('=='))
            .map(line => line.split('==')[0]);
    }
    catch (error) {
        vscode.window.showErrorMessage(`Failed to get installed packages: ${error}`);
        return [];
    }
}
async function getInstalledPackagesFromTable() {
    try {
        const { stdout } = await execAsync('pip list');
        const lines = stdout.split('\n').map((l) => l.trim()).filter(Boolean);
        const results = [];
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
    }
    catch (error) {
        vscode.window.showErrorMessage(`Failed to parse pip list: ${error}`);
        return [];
    }
}
async function getPipShowInfo(packageName) {
    try {
        const { stdout } = await execAsync(`pip show ${packageName}`);
        return stdout;
    }
    catch (error) {
        return `Error getting info for ${packageName}: ${error}`;
    }
}
async function extractPythonPackageSources(sitePackagesPath, packageName, outputDir) {
    const packagePath = path.join(sitePackagesPath, packageName);
    if (!fs.existsSync(packagePath)) {
        return 0;
    }
    const packageOutputDir = path.join(outputDir, packageName);
    fs.mkdirSync(packageOutputDir, { recursive: true });
    return await copyPythonFilesRecursively(packagePath, packageOutputDir);
}
async function copyPythonFilesRecursively(sourceDir, destDir) {
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
            }
            else if (stat.isFile() && item.endsWith('.py')) {
                fs.copyFileSync(sourcePath, destPath);
                fileCount++;
            }
        }
    }
    catch (error) {
        if (error.code === 'EACCES' || error.code === 'EPERM') {
            throw new Error('Permission denied. Please run VS Code as administrator.');
        }
        throw error;
    }
    return fileCount;
}
async function createPythonPackagesZip() {
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
                // console.log(`Extracted ${fileCount} files from ${packageName}`);
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
        await new Promise((resolve, reject) => {
            const output = fs.createWriteStream(zipPath);
            const archive = (0, archiver_1.default)('zip', { zlib: { level: 9 } });
            output.on('close', resolve);
            output.on('error', reject);
            archive.on('error', reject);
            archive.pipe(output);
            archive.directory(tempDir, false);
            archive.finalize().catch(reject);
        });
        fs.rmSync(tempDir, { recursive: true, force: true });
        return zipPath;
    }
    catch (error) {
        fs.rmSync(tempDir, { recursive: true, force: true });
        throw error;
    }
}
function activate(context) {
    // Helper function to handle analysis with specific type
    async function performAnalysis(createZipFunction, analysisType, analysisName) {
        try {
            vscode.window.showInformationMessage(`${analysisName} 분석을 시작합니다...`);
            const zipPath = await createZipFunction();
            const result = await uploadZipToPythonServer(zipPath, analysisType);
            const analysisTypeText = {
                'integrated': '통합 (취약점 + 악성코드)',
                'vulnerability': '취약점',
                'malicious': '악성코드'
            }[analysisType];
            const statusMessage = `${analysisTypeText} 분석이 시작되었습니다!`;
            vscode.window.showInformationMessage(`${statusMessage} 세션 ID: ${result.session_id}`, '대시보드 열기').then((selection) => {
                if (selection === '대시보드 열기') {
                    vscode.env.openExternal(vscode.Uri.parse(result.dashboard_url));
                }
            });
            fs.unlinkSync(zipPath);
        }
        catch (error) {
            const message = error?.message ?? String(error);
            if (message.includes('Permission denied')) {
                vscode.window.showErrorMessage('권한이 부족합니다. VS Code를 관리자 권한으로 실행해주세요.');
            }
            else if (message.includes('timeout')) {
                vscode.window.showErrorMessage('서버 연결 시간이 초과되었습니다. 서버가 실행 중인지 확인해주세요.');
            }
            else if (message.includes('ECONNREFUSED')) {
                vscode.window.showErrorMessage('서버에 연결할 수 없습니다. 서버가 실행 중인지 확인해주세요.');
            }
            else {
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
        await performAnalysis(() => createPythonOnlyZipFromFolder(workspaceFolder), 'integrated', '프로젝트 통합');
    });
    // 2. 통합 분석 - 설치된 패키지
    const disposable2 = vscode.commands.registerCommand('vscode-extension.extractPythonPackages', async () => {
        await performAnalysis(() => createPythonPackagesZip(), 'integrated', '설치된 패키지 통합');
    });
    // 3. 취약점 분석 - 프로젝트
    const disposable3 = vscode.commands.registerCommand('vscode-extension.analyzeProjectVulnerability', async () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('워크스페이스 폴더가 없습니다. 폴더를 열고 다시 시도하세요.');
            return;
        }
        await performAnalysis(() => createPythonOnlyZipFromFolder(workspaceFolder), 'vulnerability', '프로젝트 취약점');
    });
    // 4. 악성 분석 - 프로젝트
    const disposable4 = vscode.commands.registerCommand('vscode-extension.analyzeProjectMalicious', async () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('워크스페이스 폴더가 없습니다. 폴더를 열고 다시 시도하세요.');
            return;
        }
        await performAnalysis(() => createPythonOnlyZipFromFolder(workspaceFolder), 'malicious', '프로젝트 악성');
    });
    // 5. 취약점 분석 - 설치된 패키지
    const disposable5 = vscode.commands.registerCommand('vscode-extension.analyzePackagesVulnerability', async () => {
        await performAnalysis(() => createPythonPackagesZip(), 'vulnerability', '설치된 패키지 취약점');
    });
    // 6. 악성 분석 - 설치된 패키지
    const disposable6 = vscode.commands.registerCommand('vscode-extension.analyzePackagesMalicious', async () => {
        await performAnalysis(() => createPythonPackagesZip(), 'malicious', '설치된 패키지 악성');
    });
    context.subscriptions.push(disposable1, disposable2, disposable3, disposable4, disposable5, disposable6);
}
function deactivate() { }
//# sourceMappingURL=extension.js.map