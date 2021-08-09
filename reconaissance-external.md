---
title: Reconaissance - External
description: 
published: true
date: 2021-08-09T14:39:13.316Z
tags: security, reconaissance, external
editor: markdown
dateCreated: 2021-08-09T14:39:13.316Z
---

# Reconaissance - External
## Extract Metadata
Downlod files:
metagoofil -d [targetDomain.com] -l 100 -n 100 -t doc,docx,xls,xlsx,pdf -w -o metagoofil_results -f

Search for intertesting metadata:
exiftool -r *.pdf | egrep -i "Author|Creator|Email|Proucer|Template" | sort -u