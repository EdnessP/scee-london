#!/usr/bin/env python3
# Updates SongCache.xml with .pkg.drm files (!!! WIP, NOT YET DONE !!!)
# Written by Edness   v0.1   2026-07-12

import glob, os, xml.etree.cElementTree

def create_songcache(path, output=str(), user=int()):
    path = os.path.abspath(path)
    if not output:
        output = os.path.join(path, "SongCache.xml")
    output = os.path.abspath(output)

    # this xml writer is kinda lame for various reasons, might be better to write it myself later
    songs = xml.etree.cElementTree.Element("Songs")
    for file in glob.iglob(os.path.join(glob.escape(path), "**", "Pack0_*.pkg.drm"), recursive=True):
        name = os.path.split(file)[1]
        song = xml.etree.cElementTree.SubElement(songs, "Song")
        xml.etree.cElementTree.SubElement(song, "CacheFolder").text = f"Prod_Sku_{name[6:12]}"
        xml.etree.cElementTree.SubElement(song, "Package").text = name
        xml.etree.cElementTree.SubElement(song, "Size").text = str(os.path.getsize(file))
        xml.etree.cElementTree.SubElement(song, "PCL").text = "1"
        xml.etree.cElementTree.SubElement(song, "User").text = str(user)
        xml.etree.cElementTree.SubElement(song, "IsNew").text = "False"
    out = xml.etree.cElementTree.ElementTree(songs)
    out.write(output, xml_declaration=True, encoding="UTF-8")

    print("Done! Output written to", output)

if __name__ == "__main__":
    import argparse

    def c_int(id):
        if id.lower().startswith("0x"):
            return int(id[2:], 16)
        return int(id, 10)

    parser = argparse.ArgumentParser(description="Updates SongCache.xml with .pkg.drm files")
    parser.add_argument("path", type=str, help="path to scan for .pkg.drm files")
    parser.add_argument("-o", "--output", type=str, default=str(), help="path to the output xml")
    parser.add_argument("-u", "--user", type=c_int, default=int(), help="user id (optional)")

    args = parser.parse_args()
    create_songcache(args.path, args.output, args.user)