rem # you should not touch this file - this is run automatically
rem # these are run from the vs folder where the vcxproj files are
rem copy ..\readme.txt ..\out /y
rem python -c "__import__('shutil').make_archive('..\\scee_london', 'zip', '..\\out')"

rem # why didn't i think of this earlier?
cd ..
wsl ./build_all.sh msvc
