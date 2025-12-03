# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for CustosEye
# This ensures all pywebview dependencies are properly included

block_cipher = None

a = Analysis(
    ['app/console.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('data', 'data'),
        ('dashboard/static', 'dashboard/static'),
        ('dashboard/templates', 'dashboard/templates'),
        ('assets', 'assets'),
    ],
    hiddenimports=[
        # Core webview imports
        'webview',
        'webview.platforms',
        'webview.platforms.edgechromium',  # Windows uses Edge WebView2
        'webview.window',
        # Flask and web server
        'flask',
        'waitress',
        # Monitoring agents
        'psutil',
        # System tray
        'pystray',
        'PIL',
        'PIL._tkinter_finder',
        # Authentication
        'dotenv',
        'pyotp',
        'qrcode',
        'argon2',
        'bcrypt',
        # Utilities
        'openpyxl',
        'requests',
        'colorama',
        # Dashboard modules
        'dashboard.app',
        'dashboard.auth',
        'dashboard.config',
        'agent.monitor',
        'agent.integrity_check',
        'agent.network_scan',
        'agent.rules_engine',
        'algorithm.csc_engine',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CustosEye',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Keep console for error messages
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='dashboard/static/assets/favicon.ico',
)

