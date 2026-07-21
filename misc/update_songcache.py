#!/usr/bin/env python3
# Updates SongCache.xml with .pkg.drm files
# For more info see https://github.com/EdnessP/scee-london

# Usage:
#     python  update_songcache.py  "X:\path\to\songs"
#   Optional:
#     -o | --output <str> Path to the output file; can update an existing file
#     -u | --user   <int> PS3 User ID (optional, leaving it as 0 also seems to work)
#       python  update_songcache.py  "X:\path\to\songs"  -o "Y:\path\to\SongCache.xml"

# Written by Edness   v1.0   2026-07-16

import glob, os, xml.etree.ElementTree

def exists_prompt(output, prompt):
    if os.path.exists(output):
        while True:
            response = input(f"{prompt} (Y/N): ")[:1].upper()
            if response == "Y": return True
            elif response == "N": return False
            else: print("Error! Invalid response.")
    return False

def create_songcache(path, output=str(), user=int()):
    path = os.path.abspath(path)
    if not output:
        output = os.path.join(path, "SongCache.xml")
    output = os.path.abspath(output)

    exist_song = list()
    if exists_prompt(output, "Update existing output file?"):
        songs = xml.etree.ElementTree.parse(output).getroot()
        for song in songs:
            assert len(song) == 6
            assert song[0].tag == "CacheFolder"
            assert song[1].tag == "Package"
            assert song[2].tag == "Size"
            assert song[3].tag == "PCL"
            assert song[4].tag == "User"
            assert song[5].tag == "IsNew"
            assert len(song[0].text) == 15
            assert song[0].text.startswith("Prod_Sku_")
            assert len(song[1].text) == 20
            assert song[1].text.startswith("Pack0_")
            assert song[1].text.endswith(".pkg.drm")
            exist_song.append(song[0].text[9:].upper())
    else:
        songs = xml.etree.ElementTree.Element("Songs")

    # this xml writer is kinda lame for various reasons, might be better to write it myself later
    for file in glob.iglob(os.path.join(glob.escape(path), "**", "Pack0_??????.pkg.drm"), recursive=True):
        name = os.path.split(file)[1]
        song_id = name[6:12]  # the same numerical id found internally but in base 36
        if song_id.upper() in exist_song: continue
        song = xml.etree.ElementTree.SubElement(songs, "Song")
        xml.etree.ElementTree.SubElement(song, "CacheFolder").text = f"Prod_Sku_{song_id}"  # ideally should be grabbed from config.xml
        xml.etree.ElementTree.SubElement(song, "Package").text = name
        xml.etree.ElementTree.SubElement(song, "Size").text = str(os.path.getsize(file))  # unused? older games wrote it wrong anyway
        xml.etree.ElementTree.SubElement(song, "PCL").text = "1"  # ideally should be grabbed from songs_#_0.xml
        xml.etree.ElementTree.SubElement(song, "User").text = str(user)  # 0 seems to allow loading for any user
        xml.etree.ElementTree.SubElement(song, "IsNew").text = "False"
    out = xml.etree.ElementTree.ElementTree(songs)
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
