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
function buildDashboardUrl(sessionId, isML = false) {
    if (!sessionId) {
        return 'http://127.0.0.1:8000/';
    }
    return isML
        ? `http://127.0.0.1:8000/session/${sessionId}/ML`
        : `http://127.0.0.1:8000/session/${sessionId}`;
}
async function safeOpenExternal(rawUrl) {
    try {
        const url = encodeURI(rawUrl);
        const opened = await vscode.env.openExternal(vscode.Uri.parse(url));
        if (!opened) {
            throw new Error('Failed to open external URL');
        }
    }
    catch (err) {
        const selection = await vscode.window.showErrorMessage(`대시보드 URL 열기 실패: ${rawUrl}`, 'URL 복사');
        if (selection === 'URL 복사') {
            await vscode.env.clipboard.writeText(rawUrl);
            vscode.window.showInformationMessage('대시보드 URL이 클립보드에 복사되었습니다. 브라우저에 붙여넣기 해주세요.');
        }
    }
}
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
async function uploadZipToPythonServer(zipPath) {
    return uploadZipToEndpoint(zipPath, '/api/v1/upload');
}
async function uploadZipToEndpoint(zipPath, endpoint) {
    const form = new form_data_1.default();
    form.append('file', fs.createReadStream(zipPath), path.basename(zipPath));
    const url = `http://127.0.0.1:8000${endpoint}`;
    const response = await axios_1.default.post(url, form, {
        headers: form.getHeaders(),
        maxContentLength: Infinity,
        maxBodyLength: Infinity
    });
    return response.data;
}
const POLL_INTERVAL_MS = 10000; // reduce server load: poll every 10s
const POLL_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
async function waitForSessionReady(sessionId, isML = false, onProgress, token) {
    const baseUrl = 'http://127.0.0.1:8000';
    const url = `${baseUrl}/api/v1/sessions/${sessionId}`;
    const startedAt = Date.now();
    let attempt = 0;
    while (Date.now() - startedAt < POLL_TIMEOUT_MS) {
        if (token?.isCancellationRequested) {
            throw new Error('사용자가 분석 대기를 취소했습니다.');
        }
        attempt += 1;
        try {
            const res = await axios_1.default.get(url, { validateStatus: () => true });
            if (res.status === 200 && res.data && res.data.session_id) {
                return res.data;
            }
            if (res.status !== 404 && res.status >= 400) {
                throw new Error(`서버 오류: ${res.status}`);
            }
            if (onProgress) {
                onProgress(`분석 중... (시도 ${attempt})`);
            }
        }
        catch (e) {
            // 네트워크 오류는 재시도
            if (onProgress) {
                onProgress(`분석 결과 대기 중... (시도 ${attempt})`);
            }
        }
        await delay(POLL_INTERVAL_MS);
    }
    throw new Error('분석이 제한 시간 내에 완료되지 않았습니다.');
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
        const lines = stdout.split('\n').map(l => l.trim()).filter(Boolean);
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
    // Original command: Zip folder and upload (Python files only)
    const disposable1 = vscode.commands.registerCommand('vscode-extension.uploadZipToLocal', async () => {
        try {
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
            if (!workspaceFolder) {
                vscode.window.showErrorMessage('워크스페이스 폴더가 없습니다. 폴더를 열고 다시 시도하세요.');
                return;
            }
            vscode.window.showInformationMessage('Python 파일들을 압축하고 서버로 전송 중...');
            const zipPath = await createPythonOnlyZipFromFolder(workspaceFolder);
            const result = await uploadZipToPythonServer(zipPath);
            fs.unlinkSync(zipPath);
            const dashUrl = result?.dashboard_url || buildDashboardUrl(result?.session_id);
            const summary = await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: '서버가 코드를 분석 중입니다...',
                cancellable: true
            }, async (progress, token) => {
                progress.report({ message: '분석 시작' });
                return await waitForSessionReady(result.session_id, false, m => progress.report({ message: m }), token);
            });
            vscode.window.showInformationMessage(`분석 완료! 세션 ID: ${summary.session_id}`, '대시보드 열기').then(selection => {
                if (selection === '대시보드 열기') {
                    vscode.env.openExternal(vscode.Uri.parse(dashUrl));
                }
            });
        }
        catch (error) {
            const message = error?.message ?? String(error);
            vscode.window.showErrorMessage(`Upload failed: ${message}`);
        }
    });
    // New command: Extract Python packages and upload (ML endpoint)
    const disposable2 = vscode.commands.registerCommand('vscode-extension.extractPythonPackages', async () => {
        try {
            vscode.window.showInformationMessage('Python 패키지 소스코드 추출을 시작합니다...');
            const zipPath = await createPythonPackagesZip();
            const result = await uploadZipToEndpoint(zipPath, '/api/v1/upload/ML');
            fs.unlinkSync(zipPath);
            const dashUrl = result?.dashboard_url || buildDashboardUrl(result?.session_id, true);
            const summary = await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'ML 패키지 분석 진행 중...',
                cancellable: true
            }, async (progress, token) => {
                progress.report({ message: '분석 시작' });
                return await waitForSessionReady(result.session_id, true, m => progress.report({ message: m }), token);
            });
            vscode.window.showInformationMessage(`분석 완료 (ML 패키지)! 세션 ID: ${summary.session_id}`, '대시보드 열기').then(selection => {
                if (selection === '대시보드 열기') {
                    vscode.env.openExternal(vscode.Uri.parse(dashUrl));
                }
            });
        }
        catch (error) {
            const message = error?.message ?? String(error);
            if (message.includes('Permission denied')) {
                vscode.window.showErrorMessage('권한이 부족합니다. VS Code를 관리자 권한으로 실행해주세요.');
            }
            else {
                vscode.window.showErrorMessage(`Python packages extraction failed: ${message}`);
            }
        }
    });
    // New commands: Explicit upload routes for LSTM/BERT/ML
    const disposableLstm = vscode.commands.registerCommand('vscode-extension.upload.lstm', async () => {
        try {
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
            if (!workspaceFolder) {
                vscode.window.showErrorMessage('워크스페이스 폴더가 없습니다. 폴더를 열고 다시 시도하세요.');
                return;
            }
            vscode.window.showInformationMessage('LSTM 통합 분석을 위한 ZIP 생성 중...');
            const zipPath = await createPythonOnlyZipFromFolder(workspaceFolder);
            const result = await uploadZipToEndpoint(zipPath, '/api/v1/upload/lstm');
            fs.unlinkSync(zipPath);
            const dashUrl = result?.dashboard_url || buildDashboardUrl(result?.session_id);
            const summary = await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'LSTM 통합 분석 진행 중...',
                cancellable: true
            }, async (progress, token) => waitForSessionReady(result.session_id, false, m => progress.report({ message: m }), token));
            vscode.window.showInformationMessage(`분석 완료 (LSTM 통합)! 세션 ID: ${summary.session_id}`, '대시보드 열기').then(selection => {
                if (selection === '대시보드 열기') {
                    vscode.env.openExternal(vscode.Uri.parse(dashUrl));
                }
            });
        }
        catch (error) {
            const message = error?.message ?? String(error);
            vscode.window.showErrorMessage(`LSTM 업로드 실패: ${message}`);
        }
    });
    const disposableLstmMal = vscode.commands.registerCommand('vscode-extension.upload.lstm.mal', async () => {
        try {
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
            if (!workspaceFolder) {
                vscode.window.showErrorMessage('워크스페이스 폴더가 없습니다. 폴더를 열고 다시 시도하세요.');
                return;
            }
            vscode.window.showInformationMessage('LSTM 악성 전용 분석 ZIP 생성 중...');
            const zipPath = await createPythonOnlyZipFromFolder(workspaceFolder);
            const result = await uploadZipToEndpoint(zipPath, '/api/v1/upload/lstm/mal');
            fs.unlinkSync(zipPath);
            const dashUrl = result?.dashboard_url || buildDashboardUrl(result?.session_id);
            const summary = await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'LSTM 악성 분석 진행 중...',
                cancellable: true
            }, async (progress, token) => waitForSessionReady(result.session_id, false, m => progress.report({ message: m }), token));
            vscode.window.showInformationMessage(`분석 완료 (LSTM 악성)! 세션 ID: ${summary.session_id}`, '대시보드 열기').then(selection => {
                if (selection === '대시보드 열기') {
                    vscode.env.openExternal(vscode.Uri.parse(dashUrl));
                }
            });
        }
        catch (error) {
            const message = error?.message ?? String(error);
            vscode.window.showErrorMessage(`LSTM 악성 업로드 실패: ${message}`);
        }
    });
    const disposableLstmVul = vscode.commands.registerCommand('vscode-extension.upload.lstm.vul', async () => {
        try {
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
            if (!workspaceFolder) {
                vscode.window.showErrorMessage('워크스페이스 폴더가 없습니다. 폴더를 열고 다시 시도하세요.');
                return;
            }
            vscode.window.showInformationMessage('LSTM 취약점 전용 분석 ZIP 생성 중...');
            const zipPath = await createPythonOnlyZipFromFolder(workspaceFolder);
            const result = await uploadZipToEndpoint(zipPath, '/api/v1/upload/lstm/vul');
            fs.unlinkSync(zipPath);
            const dashUrl = result?.dashboard_url || buildDashboardUrl(result?.session_id);
            const summary = await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'LSTM 취약점 분석 진행 중...',
                cancellable: true
            }, async (progress, token) => waitForSessionReady(result.session_id, false, m => progress.report({ message: m }), token));
            vscode.window.showInformationMessage(`분석 완료 (LSTM 취약점)! 세션 ID: ${summary.session_id}`, '대시보드 열기').then(selection => {
                if (selection === '대시보드 열기') {
                    vscode.env.openExternal(vscode.Uri.parse(dashUrl));
                }
            });
        }
        catch (error) {
            const message = error?.message ?? String(error);
            vscode.window.showErrorMessage(`LSTM 취약 업로드 실패: ${message}`);
        }
    });
    const disposableBert = vscode.commands.registerCommand('vscode-extension.upload.bert', async () => {
        try {
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
            if (!workspaceFolder) {
                vscode.window.showErrorMessage('워크스페이스 폴더가 없습니다. 폴더를 열고 다시 시도하세요.');
                return;
            }
            vscode.window.showInformationMessage('BERT 통합 분석을 위한 ZIP 생성 중...');
            const zipPath = await createPythonOnlyZipFromFolder(workspaceFolder);
            const result = await uploadZipToEndpoint(zipPath, '/api/v1/upload/bert');
            fs.unlinkSync(zipPath);
            const dashUrl = result?.dashboard_url || buildDashboardUrl(result?.session_id);
            const summary = await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'BERT 통합 분석 진행 중...',
                cancellable: true
            }, async (progress, token) => waitForSessionReady(result.session_id, false, m => progress.report({ message: m }), token));
            vscode.window.showInformationMessage(`분석 완료 (BERT 통합)! 세션 ID: ${summary.session_id}`, '대시보드 열기').then(selection => {
                if (selection === '대시보드 열기') {
                    vscode.env.openExternal(vscode.Uri.parse(dashUrl));
                }
            });
        }
        catch (error) {
            const message = error?.message ?? String(error);
            vscode.window.showErrorMessage(`BERT 업로드 실패: ${message}`);
        }
    });
    const disposableBertMal = vscode.commands.registerCommand('vscode-extension.upload.bert.mal', async () => {
        try {
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
            if (!workspaceFolder) {
                vscode.window.showErrorMessage('워크스페이스 폴더가 없습니다. 폴더를 열고 다시 시도하세요.');
                return;
            }
            vscode.window.showInformationMessage('BERT 악성 전용 분석 ZIP 생성 중...');
            const zipPath = await createPythonOnlyZipFromFolder(workspaceFolder);
            const result = await uploadZipToEndpoint(zipPath, '/api/v1/upload/bert/mal');
            fs.unlinkSync(zipPath);
            const dashUrl = result?.dashboard_url || buildDashboardUrl(result?.session_id);
            const summary = await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'BERT 악성 분석 진행 중...',
                cancellable: true
            }, async (progress, token) => waitForSessionReady(result.session_id, false, m => progress.report({ message: m }), token));
            vscode.window.showInformationMessage(`분석 완료 (BERT 악성)! 세션 ID: ${summary.session_id}`, '대시보드 열기').then(selection => {
                if (selection === '대시보드 열기') {
                    vscode.env.openExternal(vscode.Uri.parse(dashUrl));
                }
            });
        }
        catch (error) {
            const message = error?.message ?? String(error);
            vscode.window.showErrorMessage(`BERT 악성 업로드 실패: ${message}`);
        }
    });
    const disposableBertVul = vscode.commands.registerCommand('vscode-extension.upload.bert.vul', async () => {
        try {
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
            if (!workspaceFolder) {
                vscode.window.showErrorMessage('워크스페이스 폴더가 없습니다. 폴더를 열고 다시 시도하세요.');
                return;
            }
            vscode.window.showInformationMessage('BERT 취약점 전용 분석 ZIP 생성 중...');
            const zipPath = await createPythonOnlyZipFromFolder(workspaceFolder);
            const result = await uploadZipToEndpoint(zipPath, '/api/v1/upload/bert/vul');
            fs.unlinkSync(zipPath);
            const dashUrl = result?.dashboard_url || buildDashboardUrl(result?.session_id);
            const summary = await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'BERT 취약점 분석 진행 중...',
                cancellable: true
            }, async (progress, token) => waitForSessionReady(result.session_id, false, m => progress.report({ message: m }), token));
            vscode.window.showInformationMessage(`분석 완료 (BERT 취약점)! 세션 ID: ${summary.session_id}`, '대시보드 열기').then(selection => {
                if (selection === '대시보드 열기') {
                    vscode.env.openExternal(vscode.Uri.parse(dashUrl));
                }
            });
        }
        catch (error) {
            const message = error?.message ?? String(error);
            vscode.window.showErrorMessage(`BERT 취약 업로드 실패: ${message}`);
        }
    });
    const disposableML = vscode.commands.registerCommand('vscode-extension.upload.ml', async () => {
        try {
            vscode.window.showInformationMessage('ML 패키지 분석을 위한 패키지 ZIP 생성 중...');
            const zipPath = await createPythonPackagesZip();
            const result = await uploadZipToEndpoint(zipPath, '/api/v1/upload/ML');
            const dashUrl = result?.dashboard_url || buildDashboardUrl(result?.session_id, true);
            vscode.window.showInformationMessage(`업로드 완료 (ML 패키지)! 세션 ID: ${result.session_id}`, '대시보드 열기').then(selection => {
                if (selection === '대시보드 열기') {
                    vscode.env.openExternal(vscode.Uri.parse(dashUrl));
                }
            });
            fs.unlinkSync(zipPath);
        }
        catch (error) {
            const message = error?.message ?? String(error);
            vscode.window.showErrorMessage(`ML 업로드 실패: ${message}`);
        }
    });
    context.subscriptions.push(disposable1, disposable2, disposableLstm, disposableLstmMal, disposableLstmVul, disposableBert, disposableBertMal, disposableBertVul, disposableML);
}
function deactivate() { }
//# sourceMappingURL=extension.js.map