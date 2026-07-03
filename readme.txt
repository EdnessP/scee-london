SCEE London Studio PACKAGE tool
        Made by  Edness        

https://github.com/EdnessP/scee-london


This tool extracts SCEE London Studio PACKAGE (.PKF, .PKD, .PKG, .PAK, .THEMES)
files used in a multitude of PS3 releases:
  SingStar, DanceStar Party (Everybody Dance), EyePet (Me & My Pet),
  TV Superstars, Me Motion, Aqua Vita (Aquatopia), Mesmerize,
  Operation Creature Feature, The Trials of Topoq, Tori-Emaki.
It supports all of its variants - plain, compressed, encrypted, 32/64-bit.

Some games may have an additional layer of SDAT/EDAT or disc sector encryption;
that is not handled by this tool.  You must decrypt those beforehand with other
already existing tools.


== Usage (Simple, Windows only) ==
Drag and drop the PACKAGE files onto the .EXE file.


== Usage (Proper, Windows/Linux/macOS) ==
Provide a path to the PACKAGE file(s), and optionally a path to a chosen output
directory with -o or --output through a terminal or command line interface.
Use -k or --drmkey to provide your PS3's OpenPSID for decrypting .DRM files.
Use -d or --dump to just decrypt/encrypt the PACKAGE without extracting it.
Use -s or --strip to remove the OpenPSID DRM key from the PACKAGE file.
WARNING! Stripping the DRM key will modify the input file!

Linux and macOS may require you to first run: sudo chmod +x scee_london
macOS may also require: sudo xattr -d com.apple.quarantine scee_london
after first moving it out of Downloads for it not to get quarantined.
Shell expansion for multiple input files is also supported.


== Shout-Outs ==
Special shoutout to the friends and community behind Redump.info & No-Intro.org


== Support ==
While completely optional, you can support me here if you wish:
https://ko-fi.com/edness


== License ==
SCEE London Studio PS3 PACKAGE tool
Copyright (C) 2024-2026  Edness

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
