# -*- mode: python -*-
a = Analysis(['scripts/carbonblack_threatconnect_bridge'],
             pathex=['.'],
             hiddenimports=['unicodedata'],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='carbonblack_threatconnect_bridge',
          debug=False,
          strip=False,
          upx=True,
          console=True )