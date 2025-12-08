import { app, BrowserWindow, ipcMain, dialog, shell, globalShortcut, desktopCapturer, screen } from 'electron'
import { exec, spawn } from 'node:child_process'
import path from 'node:path'
import fs from 'node:fs'
import crypto from 'node:crypto'

// --- Secure Store Implementation ---
class Store {
    private path: string;
    private encryptionKey: Buffer;

    constructor(fileName: string) {
        const userDataPath = app.getPath('userData');
        this.path = path.join(userDataPath, fileName);

        // In a real production app, use keytar or similar to store a random key in OS keychain.
        // For this scope, we derive a key from a hardcoded secret + machine ID (if available) or just a strong secret.
        // Using a fixed secret for simplicity and recoverability in this context.
        const secret = 'game-vault-secure-storage-key-v1';
        this.encryptionKey = crypto.scryptSync(secret, 'salt', 32);
    }

    get(key: string): any {
        try {
            if (!fs.existsSync(this.path)) {
                return undefined;
            }

            const data = JSON.parse(fs.readFileSync(this.path, 'utf8'));
            const value = data[key];

            if (!value) return undefined;

            // If it looks like encrypted data (starts with ENC:), decrypt it
            if (typeof value === 'string' && value.startsWith('ENC:')) {
                return this.decrypt(value.substring(4));
            }

            return value;
        } catch (error) {
            console.error('Error reading store:', error);
            return undefined;
        }
    }

    set(key: string, value: any, encrypt: boolean = false): void {
        try {
            let data: any = {};
            if (fs.existsSync(this.path)) {
                data = JSON.parse(fs.readFileSync(this.path, 'utf8'));
            }

            if (encrypt) {
                data[key] = 'ENC:' + this.encrypt(value);
            } else {
                data[key] = value;
            }

            fs.writeFileSync(this.path, JSON.stringify(data, null, 2));
        } catch (error) {
            console.error('Error writing to store:', error);
        }
    }

    private encrypt(text: any): string {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.encryptionKey, iv);
        let encrypted = cipher.update(JSON.stringify(text));
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return iv.toString('hex') + ':' + encrypted.toString('hex');
    }

    private decrypt(text: string): any {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift()!, 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', this.encryptionKey, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return JSON.parse(decrypted.toString());
    }
}

const store = new Store('data.json');

// --- IPC Handlers for Storage ---
ipcMain.handle('save-data', async (_, key: string, data: any, encrypt: boolean = false) => {
    store.set(key, data, encrypt);
    return true;
});

ipcMain.handle('load-data', async (_, key: string) => {
    return store.get(key);
});

// --- Existing IPC Handlers ---
ipcMain.handle('select-game-exe', async () => {
    const result = await dialog.showOpenDialog({
        properties: ['openFile'],
        filters: [{ name: 'Executables', extensions: ['exe'] }]
    })
    return result.filePaths[0]
})

ipcMain.handle('select-folder', async () => {
    const result = await dialog.showOpenDialog({
        properties: ['openDirectory']
    })
    return result.filePaths[0]
})

ipcMain.handle('save-backup', async (_, data: string) => {
    const result = await dialog.showSaveDialog({
        title: 'Save Backup',
        defaultPath: 'gamevault-backup.json',
        filters: [{ name: 'JSON', extensions: ['json'] }]
    });

    if (!result.canceled && result.filePath) {
        fs.writeFileSync(result.filePath, data);
        return true;
    }
    return false;
});

ipcMain.handle('load-backup', async () => {
    const result = await dialog.showOpenDialog({
        title: 'Load Backup',
        filters: [{ name: 'JSON', extensions: ['json'] }],
        properties: ['openFile']
    });

    if (!result.canceled && result.filePaths.length > 0) {
        const data = fs.readFileSync(result.filePaths[0], 'utf-8');
        return JSON.parse(data);
    }
    return null;
});

ipcMain.handle('open-path', async (_, filePath: string) => {
    shell.showItemInFolder(filePath);
})

ipcMain.handle('select-image', async () => {
    const result = await dialog.showOpenDialog({
        properties: ['openFile'],
        filters: [{ name: 'Images', extensions: ['jpg', 'png', 'webp', 'jpeg'] }]
    })
    return result.filePaths[0]
})

ipcMain.handle('launch-external', async (_, protocol: string) => {
    try {
        await shell.openExternal(protocol);
        return true;
    } catch (e) {
        console.error('Failed to open external protocol:', e);
        return false;
    }
})

ipcMain.handle('window-minimize', () => {
    win?.minimize();
});

ipcMain.handle('window-maximize', () => {
    if (win?.isMaximized()) {
        win.unmaximize();
    } else {
        win?.maximize();
    }
});

ipcMain.handle('window-close', () => {
    win?.close();
});

ipcMain.handle('launch-game', async (_, game: { executablePath: string, steamAppId?: string }) => {
    return new Promise((resolve, reject) => {
        const exeName = path.basename(game.executablePath);
        console.log(`Preparing to launch ${exeName}...`);

        if (game.steamAppId) {
            console.log(`Launching Steam game: ${game.steamAppId}`);
            shell.openExternal(`steam://run/${game.steamAppId}`);
        } else {
            console.log(`Launching executable: ${game.executablePath}`);
            const gameProcess = spawn(game.executablePath, [], {
                detached: true,
                stdio: 'ignore',
                cwd: path.dirname(game.executablePath)
            });
            gameProcess.unref();
        }

        resolve(true); // Resolve immediately to show "Running" state

        // Robust Process Tracking (Case-Insensitive)
        // We poll the process list for the specific executable name.
        // Phase 1: Wait for process to appear (max 60s)
        // Phase 2: Wait for process to disappear

        let attempts = 0;
        const maxAttempts = 30; // 30 * 2s = 60s timeout to start

        const checkProcess = () => {
            // Use /FO CSV to get structured output, then parse it manually for case-insensitive check
            exec('tasklist /FO CSV /NH', (err, stdout) => {
                if (err) {
                    console.error("Tasklist error:", err);
                    // Retry anyway
                }

                const processList = stdout.toLowerCase();
                const targetExe = exeName.toLowerCase();
                const isRunning = processList.includes(`"${targetExe}"`); // Check for "game.exe" in CSV

                if (isRunning) {
                    console.log(`Game process ${exeName} detected! Monitoring...`);
                    // Process found! Now switch to monitoring for exit.
                    const monitorInterval = setInterval(() => {
                        exec('tasklist /FO CSV /NH', (err, stdout) => {
                            const currentList = stdout.toLowerCase();
                            const stillRunning = currentList.includes(`"${targetExe}"`);

                            if (!stillRunning) {
                                clearInterval(monitorInterval);
                                console.log(`Game process ${exeName} exited.`);
                                win?.webContents.send('game-exited');
                            }
                        });
                    }, 2000);
                } else {
                    attempts++;
                    if (attempts < maxAttempts) {
                        setTimeout(checkProcess, 2000);
                    } else {
                        console.log(`Timed out waiting for ${exeName} to start.`);
                        // If we timed out, we assume it failed or we missed it. 
                        // Send exit event to reset UI.
                        win?.webContents.send('game-exited');
                    }
                }
            });
        };

        // Start looking for the process
        setTimeout(checkProcess, 2000);
    })
})

ipcMain.handle('stop-game', async (_, executablePath: string) => {
    const exeName = path.basename(executablePath);
    console.log(`Stopping game: ${exeName}`);
    return new Promise((resolve) => {
        exec(`taskkill /IM "${exeName}" /F`, (err, stdout, stderr) => {
            if (err) {
                console.error(`Failed to kill process ${exeName}:`, err);

                // Check for Access Denied
                if (stderr.includes("Access is denied") || (err as any).message?.includes("Access is denied")) {
                    console.log("Access denied. Retrying with Admin privileges...");
                    // Try running taskkill as Administrator via PowerShell
                    exec(`powershell Start-Process taskkill -ArgumentList '/IM "${exeName}" /F' -Verb RunAs`, (adminErr) => {
                        if (adminErr) {
                            console.error("Failed to kill process as Admin:", adminErr);
                            resolve(false);
                        } else {
                            console.log(`Successfully triggered Admin kill for ${exeName}`);
                            resolve(true);
                        }
                    });
                } else {
                    resolve(false);
                }
            } else {
                console.log(`Successfully killed ${exeName}`);
                resolve(true);
            }
        });
    });
});

// Helper to check registry for install path
const checkRegistryForPath = (keyPath: string, valueName: string): Promise<string | null> => {
    return new Promise((resolve) => {
        exec(`reg query "${keyPath}" /v "${valueName}"`, (err, stdout) => {
            if (err) {
                resolve(null);
                return;
            }
            // Output format:
            // HKEY_...
            //     ValueName    REG_SZ    C:\Path\To\File
            const match = stdout.match(/REG_SZ\s+(.+)/);
            if (match && match[1]) {
                resolve(match[1].trim());
            } else {
                resolve(null);
            }
        });
    });
};

ipcMain.handle('check-app-installed', async (_, appId: 'steam' | 'epic' | 'gog') => {
    const commonPaths: Record<string, string[]> = {
        steam: [
            'C:\\Program Files (x86)\\Steam\\steam.exe',
            'C:\\Program Files\\Steam\\steam.exe'
        ],
        epic: [
            'C:\\Program Files (x86)\\Epic Games\\Launcher\\Portal\\Binaries\\Win32\\EpicGamesLauncher.exe',
            'C:\\Program Files (x86)\\Epic Games\\Launcher\\Portal\\Binaries\\Win64\\EpicGamesLauncher.exe',
            'C:\\Program Files\\Epic Games\\Launcher\\Portal\\Binaries\\Win32\\EpicGamesLauncher.exe',
            'C:\\Program Files\\Epic Games\\Launcher\\Portal\\Binaries\\Win64\\EpicGamesLauncher.exe'
        ],
        gog: [
            'C:\\Program Files (x86)\\GOG Galaxy\\GalaxyClient.exe',
            'C:\\Program Files\\GOG Galaxy\\GalaxyClient.exe'
        ]
    };

    // 1. Check common paths
    const pathsToCheck = commonPaths[appId] || [];
    for (const p of pathsToCheck) {
        if (fs.existsSync(p)) {
            return true;
        }
    }

    // 2. Check Registry as fallback
    try {
        if (appId === 'steam') {
            const path = await checkRegistryForPath('HKCU\\Software\\Valve\\Steam', 'SteamExe');
            if (path && fs.existsSync(path)) return true;
        } else if (appId === 'epic') {
            // Epic doesn't always store the EXE path directly, but usually "AppDataPath" or similar in:
            // HKLM\SOFTWARE\WOW6432Node\Epic Games\EpicGamesLauncher
            // Or HKLM\SOFTWARE\Epic Games\EpicGamesLauncher
            let path = await checkRegistryForPath('HKLM\\SOFTWARE\\WOW6432Node\\Epic Games\\EpicGamesLauncher', 'AppDataPath');
            if (path) {
                // AppDataPath usually points to the Data folder, not the exe. 
                // But if the key exists, it's likely installed.
                return true;
            }
        } else if (appId === 'gog') {
            const path = await checkRegistryForPath('HKLM\\SOFTWARE\\WOW6432Node\\GOG.com\\GalaxyClient', 'clientExecutable');
            if (path && fs.existsSync(path)) return true;
        }
    } catch (e) {
        console.error(`Registry check failed for ${appId}:`, e);
    }

    return false;
});

// 🚧 Use ['ENV_NAME'] avoid vite:define plugin - Vite@2.x
const VITE_DEV_SERVER_URL = process.env['VITE_DEV_SERVER_URL']

let win: BrowserWindow | null = null

ipcMain.handle('scan-games', async (_, customPath?: string) => {
    console.log('Starting smart game scan...', customPath ? `Custom path: ${customPath}` : 'Full scan');
    const foundGames: { name: string, path: string, steamAppId?: string }[] = []

    // --- Helper: Get all mounted drives ---
    const getDrives = async (): Promise<string[]> => {
        return new Promise((resolve) => {
            exec('wmic logicaldisk get name', (error, stdout) => {
                if (error) {
                    resolve(['C:', 'D:', 'E:']); // Fallback
                    return;
                }
                const drives = stdout.split('\n')
                    .map(line => line.trim())
                    .filter(line => /^[A-Z]:$/.test(line));
                resolve(drives.length > 0 ? drives : ['C:', 'D:', 'E:']);
            });
        });
    };

    const drives = await getDrives();
    console.log('Detected drives:', drives);

    // --- Definitions ---
    const blocklist = [
        'unins', 'setup', 'update', 'crash', 'config', 'redist', 'framework', 'helper', 'sys', 'dx', 'vcredist',
        'microsoft', 'windows', 'common files', 'internet explorer', 'reference assemblies', 'windows defender'
    ];

    const gameSignatures = [
        'steam_api.dll', 'steam_api64.dll', 'galaxy.dll', 'UnityPlayer.dll', 'fmod.dll', 'D3Dcompiler_47.dll',
        'os_api.dll', 'bink2w64.dll'
    ];

    const hasGameSignatures = (dir: string) => {
        try {
            return fs.readdirSync(dir).some(f => gameSignatures.includes(f));
        } catch { return false; }
    };

    const parseAcf = (content: string) => {
        const nameMatch = content.match(/"name"\s+"([^"]+)"/i);
        const installDirMatch = content.match(/"installdir"\s+"([^"]+)"/i);
        const appIdMatch = content.match(/"appid"\s+"(\d+)"/i);
        if (nameMatch && installDirMatch) {
            return {
                name: nameMatch[1],
                installDir: installDirMatch[1],
                appId: appIdMatch ? appIdMatch[1] : undefined
            };
        }
        return null;
    };

    // --- Strategy 2: Manual Scan (Recursive) ---
    const scanManualDir = (rootDir: string, currentDepth: number = 0, maxDepth: number = 3, strict: boolean = false) => {
        if (!fs.existsSync(rootDir)) return;
        if (currentDepth > maxDepth) return;

        try {
            const folders = fs.readdirSync(rootDir);
            for (const folder of folders) {
                if (blocklist.some(b => folder.toLowerCase().includes(b))) continue;
                const gamePath = path.join(rootDir, folder);

                try {
                    const stats = fs.statSync(gamePath);
                    if (!stats.isDirectory()) continue;

                    // Check if this folder IS a game
                    const hasSigs = hasGameSignatures(gamePath);
                    const files = fs.readdirSync(gamePath);
                    const exes = files.filter(f => f.toLowerCase().endsWith('.exe'));
                    const validExes = exes.filter(e => !blocklist.some(b => e.toLowerCase().includes(b)));

                    let isGame = false;
                    let bestExe = '';

                    if (hasSigs) {
                        isGame = true;
                    } else if (validExes.length > 0) {
                        // Heuristic: If it has a large exe or an exe matching the folder name
                        const matchingExe = validExes.find(e => e.toLowerCase().includes(folder.toLowerCase()));
                        if (matchingExe) {
                            bestExe = matchingExe;
                            isGame = true;
                        } else if (!strict) {
                            // Find largest exe
                            const sortedExes = validExes.sort((a, b) => {
                                try {
                                    return fs.statSync(path.join(gamePath, b)).size - fs.statSync(path.join(gamePath, a)).size;
                                } catch { return 0; }
                            });
                            const largestExe = sortedExes[0];
                            const largestSize = fs.statSync(path.join(gamePath, largestExe)).size;

                            // If exe is > 20MB, likely a game
                            if (largestSize > 20 * 1024 * 1024) {
                                bestExe = largestExe;
                                isGame = true;
                            }
                        }
                    }

                    if (isGame) {
                        if (!bestExe && validExes.length > 0) {
                            bestExe = validExes.find(e => e.toLowerCase().includes(folder.toLowerCase())) || validExes[0];
                        }

                        if (bestExe) {
                            foundGames.push({ name: folder, path: path.join(gamePath, bestExe) });
                            // STOP recursing down this branch if we found a game
                            continue;
                        }
                    }

                    // If not a game (or we want to be aggressive), recurse
                    // But if we found a game, we `continue`d above, so we only reach here if NOT a game
                    scanManualDir(gamePath, currentDepth + 1, maxDepth, strict);

                } catch { }
            }
        } catch { }
    };

    // If custom path is provided, ONLY scan that path using manual scan strategy
    if (customPath) {
        console.log(`Scanning custom path: ${customPath}`);
        // Use deeper recursion (depth 5) for custom paths to ensure we find nested games
        scanManualDir(customPath, 0, 5, false);

        // Deduplicate and return immediately
        const uniqueGames = foundGames.filter((game, index, self) =>
            index === self.findIndex((t) => (t.path === game.path))
        )
        const finalGames: { name: string, path: string, steamAppId?: string }[] = [];
        const names = new Set();
        for (const game of uniqueGames) {
            if (!names.has(game.name)) {
                names.add(game.name);
                finalGames.push(game);
            }
        }
        console.log(`Custom scan complete. Found ${finalGames.length} games.`);
        return finalGames;
    }

    // --- Strategy 1: Steam Manifest Scanning ---
    const steamPaths = [
        'C:\\Program Files (x86)\\Steam',
        'C:\\Program Files\\Steam',
    ];
    for (const drive of drives) {
        steamPaths.push(`${drive}\\SteamLibrary`);
        steamPaths.push(`${drive}\\Steam`);
    }

    // Parse libraryfolders.vdf
    const potentialSteamRoots = [
        'C:\\Program Files (x86)\\Steam',
        'C:\\Program Files\\Steam',
        ...drives.map(d => `${d}\\Steam`)
    ];

    for (const root of potentialSteamRoots) {
        const vdfPath = path.join(root, 'steamapps', 'libraryfolders.vdf');
        if (fs.existsSync(vdfPath)) {
            try {
                const content = fs.readFileSync(vdfPath, 'utf-8');
                const pathMatches = content.match(/"path"\s+"([^"]+)"/g);
                if (pathMatches) {
                    pathMatches.forEach(match => {
                        const libPath = match.split('"')[3].replace(/\\\\/g, '\\');
                        if (!steamPaths.includes(libPath)) {
                            steamPaths.push(libPath);
                        }
                    });
                }
            } catch (e) {
                console.error('Error parsing libraryfolders.vdf:', e);
            }
        }
    }

    for (const steamPath of steamPaths) {
        const steamAppsPath = path.join(steamPath, 'steamapps');
        if (fs.existsSync(steamAppsPath)) {
            try {
                const files = fs.readdirSync(steamAppsPath);
                for (const file of files) {
                    if (file.startsWith('appmanifest_') && file.endsWith('.acf')) {
                        try {
                            const content = fs.readFileSync(path.join(steamAppsPath, file), 'utf-8');
                            const gameData = parseAcf(content);
                            if (gameData) {
                                const gamePath = path.join(steamAppsPath, 'common', gameData.installDir);
                                if (fs.existsSync(gamePath)) {
                                    try {
                                        const gameFiles = fs.readdirSync(gamePath);
                                        const exes = gameFiles.filter(f => f.toLowerCase().endsWith('.exe'));
                                        let bestExe = '';
                                        bestExe = exes.find(e => e.toLowerCase().includes(gameData.installDir.toLowerCase())) || '';
                                        if (!bestExe) bestExe = exes.find(e => ['launcher.exe', 'game.exe', 'start.exe'].includes(e.toLowerCase())) || '';
                                        if (!bestExe && exes.length > 0) {
                                            const exeSizes = exes.map(e => {
                                                try { return { name: e, size: fs.statSync(path.join(gamePath, e)).size }; }
                                                catch { return { name: e, size: 0 }; }
                                            });
                                            exeSizes.sort((a, b) => b.size - a.size);
                                            bestExe = exeSizes[0].name;
                                        }
                                        if (bestExe) {
                                            foundGames.push({
                                                name: gameData.name,
                                                path: path.join(gamePath, bestExe),
                                                steamAppId: gameData.appId
                                            });
                                        }
                                    } catch (e) { }
                                }
                            }
                        } catch (e) { }
                    }
                }
            } catch (e) { }
        }
    }

    const commonGameRoots = [
        'C:\\Games',
        'C:\\Program Files\\Epic Games',
        'C:\\Program Files (x86)\\Epic Games',
        'C:\\Program Files\\GOG Galaxy\\Games',
        'C:\\GOG Galaxy\\Games',
        'C:\\Program Files (x86)\\Ubisoft\\Ubisoft Game Launcher\\games',
        'C:\\Program Files\\Ubisoft\\Ubisoft Game Launcher\\games',
        'C:\\XboxGames',
    ];
    for (const drive of drives) {
        if (drive === 'C:') continue;
        commonGameRoots.push(`${drive}\\Games`);
        commonGameRoots.push(`${drive}\\Epic Games`);
        commonGameRoots.push(`${drive}\\Program Files\\Epic Games`);
        commonGameRoots.push(`${drive}\\GOG Galaxy\\Games`);
    }

    for (const root of commonGameRoots) {
        scanManualDir(root, 0, 3, true);
    }

    // --- Strategy 3: Registry Scan (DISABLED for general scan to avoid non-game apps) ---
    // Only scan registry if explicitly requested or if we find a way to filter better.
    // For now, we rely on standard paths and manual scans.
    /*
    const scanRegistry = () => {
        return new Promise<void>((resolve) => {
            exec('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" /s', (err, stdout) => {
                if (err) { resolve(); return; }
                const lines = stdout.split('\n');
                let currentName = '';
                let currentLocation = '';
                for (const line of lines) {
                    if (line.trim().startsWith('DisplayName')) currentName = line.split('REG_SZ')[1]?.trim();
                    if (line.trim().startsWith('InstallLocation')) currentLocation = line.split('REG_SZ')[1]?.trim();
                    if (currentName && currentLocation && line.trim() === '') {
                        if (currentLocation && fs.existsSync(currentLocation)) {
                            const hasSigs = hasGameSignatures(currentLocation);
                            const isGameFolder = currentLocation.toLowerCase().includes('games') || currentLocation.toLowerCase().includes('steam') || currentLocation.toLowerCase().includes('epic');
                            if (hasSigs || isGameFolder) {
                                try {
                                    const files = fs.readdirSync(currentLocation);
                                    const exes = files.filter(f => f.toLowerCase().endsWith('.exe'));
                                    let bestExe = exes.find(e => e.toLowerCase().includes(currentName.toLowerCase()));
                                    if (!bestExe) bestExe = exes.sort((a, b) => fs.statSync(path.join(currentLocation, b)).size - fs.statSync(path.join(currentLocation, a)).size)[0];
                                    if (bestExe) {
                                        foundGames.push({ name: currentName, path: path.join(currentLocation, bestExe) });
                                    }
                                } catch (e) { }
                            }
                        }
                        currentName = '';
                        currentLocation = '';
                    }
                }
                resolve();
            });
        });
    }

    await scanRegistry();
    */

    // Deduplicate
    const uniqueGames = foundGames.filter((game, index, self) =>
        index === self.findIndex((t) => (t.path === game.path))
    )
    const finalGames: { name: string, path: string, steamAppId?: string }[] = [];
    const names = new Set();
    for (const game of uniqueGames) {
        if (!names.has(game.name)) {
            names.add(game.name);
            finalGames.push(game);
        }
    }

    console.log(`Scan complete. Found ${finalGames.length} games.`)
    return finalGames
})

ipcMain.handle('get-game-screenshots', async (_, gameName: string) => {
    try {
        const screenshotsDir = path.join(app.getPath('userData'), 'screenshots', gameName);
        if (!fs.existsSync(screenshotsDir)) return [];

        const files = fs.readdirSync(screenshotsDir);
        return files
            .filter(file => file.endsWith('.png'))
            .map(file => `media://${gameName}/${file}`);
    } catch (error) {
        console.error('Failed to get screenshots:', error);
        return [];
    }
});

ipcMain.handle('open-screenshots-folder', async (_, gameName: string) => {
    const screenshotsDir = path.join(app.getPath('userData'), 'screenshots', gameName);
    if (!fs.existsSync(screenshotsDir)) {
        fs.mkdirSync(screenshotsDir, { recursive: true });
    }
    await shell.openPath(screenshotsDir);
});

// --- Protocol Registration ---
import { protocol } from 'electron';

protocol.registerSchemesAsPrivileged([
    { scheme: 'media', privileges: { secure: true, standard: true, supportFetchAPI: true, corsEnabled: true } }
]);

app.whenReady().then(() => {
    protocol.registerFileProtocol('media', (request, callback) => {
        const url = request.url.replace('media://', '');
        try {
            const decodedUrl = decodeURIComponent(url);
            // Expected format: media://gameName/filename.png
            // But we need to map it to userData/screenshots/gameName/filename.png
            // The URL comes as "gameName/filename.png"

            // Security check: prevent directory traversal
            if (decodedUrl.includes('..')) {
                callback({ path: '' }); // Block traversal
                return;
            }

            const filePath = path.join(app.getPath('userData'), 'screenshots', decodedUrl);
            callback({ path: filePath });
        } catch (error) {
            console.error('Failed to handle media protocol:', error);
            callback({ path: '' });
        }
    });

    createWindow();
    startGlobalMonitoring();
});

// --- Logging Helper ---
const logFile = path.join(process.cwd(), 'debug_log.txt');
const log = (msg: string) => {
    try {
        fs.appendFileSync(logFile, `[${new Date().toISOString()}] ${msg}\n`);
    } catch (e) {
        console.error("Failed to write to log file:", e);
    }
};

// --- Screenshot Logic ---
const takeScreenshotNew = async (gameName: string, executablePath?: string) => {
    log(`Attempting to take screenshot for ${gameName} (Exe: ${executablePath})...`);
    try {
        const primaryDisplay = screen.getPrimaryDisplay();

        // Get all sources (windows and screens)
        const sources = await desktopCapturer.getSources({
            types: ['window', 'screen'],
            thumbnailSize: primaryDisplay.size, // Request full resolution
            fetchWindowIcons: false
        });

        let targetSource = null;
        const exeName = executablePath ? path.basename(executablePath, path.extname(executablePath)).toLowerCase() : '';

        // 1. Try to find a window matching the game title
        if (!targetSource) {
            targetSource = sources.find(s => s.name.toLowerCase() === gameName.toLowerCase());
            if (targetSource) log(`Found window matching game title: ${targetSource.name}`);
        }

        // 2. Try to find a window matching the executable name
        if (!targetSource && exeName) {
            targetSource = sources.find(s => s.name.toLowerCase().includes(exeName));
            if (targetSource) log(`Found window matching executable name: ${targetSource.name}`);
        }

        // 3. Try fuzzy match on game title
        if (!targetSource) {
            targetSource = sources.find(s => s.name.toLowerCase().includes(gameName.toLowerCase()));
            if (targetSource) log(`Found window fuzzy matching game title: ${targetSource.name}`);
        }

        // 4. Fallback to primary display
        if (!targetSource) {
            log("No matching window found. Falling back to primary display.");
            targetSource = sources.find(s => s.display_id === primaryDisplay.id.toString()) || sources.find(s => s.name === 'Entire Screen') || sources[0];
        }

        if (targetSource) {
            const image = targetSource.thumbnail;
            const screenshotsDir = path.join(app.getPath('userData'), 'screenshots', gameName);

            if (!fs.existsSync(screenshotsDir)) {
                fs.mkdirSync(screenshotsDir, { recursive: true });
            }

            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `screenshot-${timestamp}.png`;
            const filePath = path.join(screenshotsDir, filename);

            fs.writeFileSync(filePath, image.toPNG());
            log(`Screenshot saved to: ${filePath}`);

            // Notify renderer
            win?.webContents.send('screenshot-captured', { path: filePath, gameName });
        } else {
            log("No source found for screenshot.");
        }
    } catch (error) {
        log(`Failed to take screenshot: ${error}`);
        console.error('Failed to take screenshot:', error);
    }
};

const takeScreenshot = async (gameName: string) => {
    log(`Attempting to take screenshot for ${gameName}...`);
    try {
        const displays = screen.getAllDisplays();
        const primaryDisplay = screen.getPrimaryDisplay();

        // Get sources with high resolution (matching the display size)
        const sources = await desktopCapturer.getSources({
            types: ['screen'],
            thumbnailSize: primaryDisplay.size // Request full resolution
        });

        const primarySource = sources.find(s => s.display_id === primaryDisplay.id.toString()) || sources[0];

        if (primarySource) {
            const image = primarySource.thumbnail;
            const screenshotsDir = path.join(app.getPath('userData'), 'screenshots', gameName);

            if (!fs.existsSync(screenshotsDir)) {
                fs.mkdirSync(screenshotsDir, { recursive: true });
            }

            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `screenshot-${timestamp}.png`;
            const filePath = path.join(screenshotsDir, filename);

            fs.writeFileSync(filePath, image.toPNG());
            log(`Screenshot saved to: ${filePath}`);

            // Notify renderer
            win?.webContents.send('screenshot-captured', { path: filePath, gameName });
        } else {
            log("No primary source found for screenshot.");
        }
    } catch (error) {
        log(`Failed to take screenshot: ${error}`);
        console.error('Failed to take screenshot:', error);
    }
};

const registerScreenshotShortcut = (gameName: string, executablePath?: string) => {
    log(`Attempting to register screenshot shortcut for ${gameName}`);
    const shortcuts = ['F12', 'CommandOrControl+F12', 'F9'];
    let registered = false;

    for (const key of shortcuts) {
        try {
            if (globalShortcut.isRegistered(key)) {
                log(`${key} is already registered. Unregistering first...`);
                globalShortcut.unregister(key);
            }

            const ret = globalShortcut.register(key, () => {
                log(`${key} pressed - Taking screenshot...`);
                takeScreenshotNew(gameName, executablePath);
            });

            if (ret) {
                log(`Screenshot shortcut (${key}) registered successfully.`);
                // Notify renderer about the active shortcut
                win?.webContents.send('shortcut-registered', key);
                registered = true;
                break; // Stop after first successful registration
            } else {
                log(`Failed to register ${key}.`);
            }
        } catch (err) {
            log(`Error registering ${key}: ${err}`);
        }
    }

    if (!registered) {
        log("All shortcut registration attempts failed.");
        win?.webContents.send('shortcut-registration-failed');
    }
};

const unregisterScreenshotShortcut = () => {
    // Unregister all potential shortcuts
    const shortcuts = ['F12', 'CommandOrControl+F12', 'F9'];
    shortcuts.forEach(key => {
        if (globalShortcut.isRegistered(key)) {
            globalShortcut.unregister(key);
            log(`Screenshot shortcut (${key}) unregistered`);
        }
    });
};

// --- Global Game Monitoring ---
let globalMonitorInterval: NodeJS.Timeout | null = null;

const startGlobalMonitoring = () => {
    if (globalMonitorInterval) return;

    console.log("Starting global game monitoring...");
    log("Starting global game monitoring...");

    // Track running games by executable path to avoid duplicates and handle exits
    const runningGames = new Set<string>();
    let activeGameName: string | null = null; // Track active game for screenshots

    globalMonitorInterval = setInterval(async () => {
        // 1. Get list of games from store
        const gamesData = store.get('games');

        if (!gamesData || !Array.isArray(gamesData) || gamesData.length === 0) {
            return;
        }

        // 2. Get running processes
        exec('tasklist /FO CSV /NH', (err, stdout) => {
            if (err) {
                log(`Tasklist error: ${err.message}`);
                return;
            }
            const processList = stdout.toLowerCase();

            // 3. Check for matches and handle state changes
            const currentDetectedPaths = new Set<string>();

            for (const game of gamesData) {
                if (game.executablePath) {
                    const exeName = path.basename(game.executablePath).toLowerCase();
                    const fullPath = game.executablePath.toLowerCase();

                    // Check for exact match in CSV format "image.exe"
                    if (processList.includes(`"${exeName}"`)) {
                        currentDetectedPaths.add(fullPath);

                        if (!runningGames.has(fullPath)) {
                            // NEWLY DETECTED
                            log(`MATCH FOUND! ${exeName} started.`);
                            runningGames.add(fullPath);
                            win?.webContents.send('game-detected', game);

                            // Register screenshot shortcut for this game
                            // If multiple games start, the last one takes the shortcut focus
                            activeGameName = game.title;
                            registerScreenshotShortcut(game.title, game.executablePath);
                        }
                    }
                }
            }

            // 4. Check for exits
            // If a game was in runningGames but is NOT in currentDetectedPaths, it stopped.
            for (const runningPath of runningGames) {
                if (!currentDetectedPaths.has(runningPath)) {
                    // GAME EXITED
                    log(`Game exited: ${path.basename(runningPath)}`);
                    runningGames.delete(runningPath);

                    // Find the game object to send back
                    const game = gamesData.find((g: any) => g.executablePath?.toLowerCase() === runningPath);
                    if (game) {
                        win?.webContents.send('game-exited', game);

                        // Unregister shortcut if this was the active game
                        if (activeGameName === game.title) {
                            unregisterScreenshotShortcut();
                            activeGameName = null;

                            // If there are other running games, register shortcut for one of them
                            if (runningGames.size > 0) {
                                const nextGamePath = Array.from(runningGames)[0];
                                const nextGame = gamesData.find((g: any) => g.executablePath?.toLowerCase() === nextGamePath);
                                if (nextGame) {
                                    activeGameName = nextGame.title;
                                    registerScreenshotShortcut(nextGame.title, nextGame.executablePath);
                                }
                            }
                        }
                    }
                }
            }
        });
    }, 5000); // Check every 5 seconds
};

function createWindow() {
    const preloadPath = path.join(__dirname, 'preload.js')
    console.log('Preload path:', preloadPath)

    win = new BrowserWindow({
        width: 1280,
        height: 800,
        minWidth: 1024,
        minHeight: 600,
        icon: path.join(process.env.VITE_PUBLIC || path.join(__dirname, '../src/public'), 'VAULTED.ico'),
        webPreferences: {
            preload: preloadPath,
            nodeIntegration: true,
            contextIsolation: true,
            webSecurity: false, // Allow loading local resources (ASAR)
        },
        frame: false, // Custom title bar
        titleBarStyle: 'hidden',
        title: 'VAULTED Game Launcher',
        backgroundColor: '#000000',
    })

    // Block Ctrl+Shift+I (DevTools)
    win.webContents.on('before-input-event', (event, input) => {
        if (input.control && input.shift && input.key.toLowerCase() === 'i') {
            event.preventDefault()
            console.log('Blocked DevTools shortcut')
        }
        // Also block F12 just in case
        if (input.key === 'F12') {
            event.preventDefault()
            console.log('Blocked F12 shortcut')
        }
    })

    // Test active push message to Renderer-process.
    win.webContents.on('did-finish-load', () => {
        win?.webContents.send('main-process-message', (new Date).toLocaleString())

        // Auto-Update Check
        if (app.isPackaged) {
            const { autoUpdater } = require('electron-updater');
            autoUpdater.checkForUpdatesAndNotify();

            autoUpdater.on('update-available', () => {
                win?.webContents.send('update-available');
            });

            autoUpdater.on('update-downloaded', () => {
                win?.webContents.send('update-downloaded');
            });
        }
    })

    if (VITE_DEV_SERVER_URL) {
        win.loadURL(VITE_DEV_SERVER_URL)
    } else {
        // Use relative path loading which works best with ASAR
        const indexPath = 'dist/index.html';
        console.log('Loading production index from (relative):', indexPath);
        win.loadFile(indexPath);
    }

    // DEBUG: Open DevTools in production to see errors
    // win.webContents.openDevTools();
}

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit()
        win = null
    }
})

app.on('activate', () => {
    // On OS X it's common to re-create a window in the app when the
    // dock icon is clicked and there are no other windows open.
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow()
    }
})

// app.whenReady moved up to protocol registration
