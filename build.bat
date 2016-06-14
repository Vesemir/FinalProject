PUSHD "lib/seq_analyzer/scoring"
call build_compare_samples.bat
POPD
pyinstaller cli-launcher.py --onefile --hidden-import=h5py.defs --hidden-import=h5py.utils --hidden-import=h5py.h5ac --hidden-import=h5py._proxy