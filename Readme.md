# SQLShot
A collection of maintenance scripts around [OneShot](https://github.com/drygdryg/OneShot)

SQLShot is meant as a base where you can store data from multiple related projects and easily work with them.
It manages its own SQL database, `SQLShot.db`.

## Processed data
 - report from OneShot
 - [WiGLE](https://github.com/wiglenet/wigle-wifi-wardriving) .csv
 - [WiGLE Companion](https://github.com/drygdryg/wigle_companion) DB
 - folder of PINs
 - [`vulnwsc.txt`](https://github.com/drygdryg/OneShot/blob/master/vulnwsc.txt) from OneShot

## Features
 - find vulnerable AP models that are not yet in `vulnwsc.txt`
 - show statistics of your data
 - built upon `make`, each rule represents one action
 - fast and sleek code thanks to using SQL

### List of actions
For description of actions (Makefile rules), please refer to the Makefile, where each rule is commented
 - **statistics**
   - stats
   - correlation
   - stats_comp_devices
   - stats_oneshot_devices
 - merge
 - merge_pins
 - merge_kml
 - sniper
 - find_model
 - vuln_all
 - vuln_new
 - **imports**
   - import
   - import_companion
   - import_oneshot
   - import_pins
   - import_vulnwsc
   - import_wigle
   - import_wigle_csv
   - import_wigle_companion
   - pins_to_csv

## Requirements
 - `make`
 - `sqlite3`
 - `python3`

## Quick Start
 - first, copy your files (stored.csv, vulnwsc.txt, networks.db,...) to SQLShot`s folder,
 - run `make import` (a shortcut for running all imports),
 - if import went well, the data are in `SQLShot.db`, ready to work with
 - run any action you wish, maybe start with `make stats`? ;)

## TODOs
 - importing WiGLE from DB (export to csv in Android can take long time)
 - accept arbitarily named files
 - produce .kml in GPS merger
 - use natural join
