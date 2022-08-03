#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""This script prepares documentation files for mkdocs."""

import os
import sys
import shutil
import re

# Output directory for document sources
if len(sys.argv) <= 2:
    print("Use: python", sys.argv[0], "<output-directory> <repository-url>")
    sys.exit(1)
else:
    outdir  = sys.argv[1]
    repourl = sys.argv[2]

# Regex
reLinks  = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
reURL    = re.compile(r'[A-Za-z0-9]+://[A-Za-z0-9%-_]+(/[A-Za-z0-9%-_])*(#|\\?)[A-Za-z0-9%-_&=]*')
reMAIL   = re.compile(r'mailto:.*')
reANCHOR = re.compile(r'^#.*')

# All extensions for document sources
docsources = [".md", ".markdown", ".txt", ".png", ".svg", ".gif", ".jpg", ".jpeg"]
# Extensions for markdown files
mkdfiles   = [".md", ".markdown"]

# Create output directory
os.makedirs(outdir, exist_ok=True)

# Search for all document sources in repository
pwd = os.getcwd()
for root, sub, files in os.walk(pwd):
    for f in files:
        fstr  = os.path.splitext(f)
        fext  = fstr[len(fstr) - 1]
        try:
            # Only get files with extensions in the list
            ext   = docsources.index(fext)
            fpath = os.path.join(root, f)
            rpath = os.path.relpath(fpath, start=pwd)

            # Get directory path from file
            dpath = os.path.dirname(rpath)

            # Don't look on output directory
            if os.path.commonpath([dpath, outdir]) == outdir:
                break

            # Create corresponding directory
            npath = os.path.join(outdir, dpath)
            if os.path.isdir(npath) is False:
                try:
                    os.makedirs(npath, exist_ok=True)
                except OSError as error:
                    print(error)

            # Destination file
            destfile = os.path.join(npath, f)

            # Process document source file
            try:
                sidx = mkdfiles.index(docsources[ext])
                with open(fpath, encoding=sys.getdefaultencoding()) as fp:
                    with open(destfile, "w", encoding=sys.getdefaultencoding()) as fout:
                        ftxt = fp.read()

                        # Search for all markdown links in the file
                        mdlinks = reLinks.findall(ftxt)

                        for l in mdlinks:
                            # If the link is not an URL, check if it points to a
                            # non-document source file. If so, convert it to
                            # an URL for source code repository
                            link = l[1].strip()
                            if reURL.match(link) or reANCHOR.match(link) or reMAIL.match(link):
                                continue
                            # Not an URL, remove anchor link (if exist)
                            flink = re.sub(r'#.*','',link)

                            try:
                                # Get file extension of the link
                                lstr = os.path.splitext(flink)
                                lext = lstr[len(lstr) - 1]
                                didx = docsources.index(lext)
                                # It's a document source, we don't need to process
                                continue
                            except ValueError:
                                # Build the full URL for the link
                                lrpath = os.path.relpath(fpath, start=pwd)
                                ldpath = os.path.dirname(lrpath)
                                lurl   = repourl + "/" + ldpath + "/" + flink
                                # Substitute link with the full URL in the text
                                ftxt = ftxt.replace("(" + flink, "(" + lurl)

                        fout.write(ftxt)
                        fout.close()
                        fp.close()
            except ValueError:
                # Not a source file, just copy the file
                shutil.copy(fpath, destfile)
        finally:
            continue
