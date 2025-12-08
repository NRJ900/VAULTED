# VAULTED

**The Ultimate Unified Game Launcher**

VAULTED is a modern, open-source game launcher designed to unify your gaming libraries into a single, beautiful interface. Stop juggling multiple launchers—access all your games from one secure, premium dashboard.

---

## 🚀 Key Features

*   **Unified Library**: Automatically scans and imports games from **Steam**, **Epic Games Store**, and **GOG Galaxy**.
*   **Smart Scanning**: Detects games installed across multiple drives and custom locations.
*   **Playtime Tracking**: Track your hours played for every game, regardless of the platform.
*   **Gamification**: Earn points for playing, unlock custom themes, and customize your dashboard.
*   **Screen Capture**: Built-in screenshot tool (Control + F12) to capture your best gaming moments.
*   **Privacy First**: All data is stored locally and encrypted. No accounts, no tracking servers.
*   **Premium UI**: A stunning, parallax-enabled interface with animated game tiles and dynamic themes.

---

## 🖥️ System Requirements

*   **OS**: Windows 10 or Windows 11 (64-bit)
*   **Processor**: Modern 64-bit CPU
*   **Memory**: 4GB RAM recommended
*   **Storage**: ~800MB free space

---

## 📥 How to Install

1.  Go to the **[Releases](../../releases)** page of this repository.
2.  Download the latest installer (e.g., `VAULTED Setup 1.0.0.exe`).
3.  Run the installer.
4.  Launch VAULTED and start scanning your library!

---

## 👨‍💻 For Developers (Open Source)

VAULTED is built with modern web technologies on top of Electron. Contributions are welcome!

### Tech Stack
*   **Core**: [Electron](https://www.electronjs.org/)
*   **Framework**: [React](https://reactjs.org/) + [TypeScript](https://www.typescriptlang.org/)
*   **Build Tool**: [Vite](https://vitejs.dev/)
*   **Styling**: [TailwindCSS](https://tailwindcss.com/) + Shadcn/UI

### Running Locally

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/NRJ900/VAULTED.git
    cd VAULTED
    ```

2.  **Install Dependencies**:
    ```bash
    npm install
    ```

3.  **Run in Development Mode**:
    ```bash
    npm run dev
    ```
    *(This starts the Vite server and the Electron main process with hot-reload)*

4.  **Build for Production**:
    ```bash
    npm run electron:build
    ```
    *(The output installer will be in the `dist` folder)*

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

*Created by [NRJ900](https://github.com/NRJ900)*
