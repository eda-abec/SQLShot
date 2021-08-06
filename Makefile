### SQLShot
# a tool built upon Makefile and SQL
# to parse output of OneShot, WiGLE and wigle_companion
# 
# eda-abec, 04/2021


## configuration

INTERPRETER = sqlite3
DB_FILE = SQLShot.db

ORDER = DESC

MODEL_FORMAT = model || ' ' || model_number



.ONESHELL:

## queries

# Prints all discovered devices, that work with OneShot
# input:       none
# uses tables: oneshot, wigle_companion
# output:      devices
vuln_all:
	@$(INTERPRETER) $(DB_FILE) \
		"SELECT device_name || '/' || $(MODEL_FORMAT) AS device FROM wigle_companion \
		INNER JOIN oneshot ON wigle_companion.bssid = oneshot.bssid \
		GROUP BY model, model_number;"

# Prints newly discovered devices - that work with OneShot,
#                                   yet are not in vulnwsc
# input:       none
# uses tables: oneshot, wigle_companion, vulnwsc
# output:      devices
vuln_new:
	@$(INTERPRETER) $(DB_FILE) -header -line \
		"SELECT device_name || '/' || $(MODEL_FORMAT) AS device, oneshot.bssid, oneshot.essid, oneshot.date FROM wigle_companion \
		INNER JOIN oneshot ON wigle_companion.bssid = oneshot.bssid \
		WHERE wigle_companion.model || ' ' || wigle_companion.model_number NOT IN \
		(SELECT device FROM vulnwsc);"

	echo ""
	echo ""
	echo "PIN-only"
	$(INTERPRETER) $(DB_FILE) -header -line \
		"SELECT device_name || '/' || $(MODEL_FORMAT) AS device, pins.bssid FROM wigle_companion \
		INNER JOIN pins ON wigle_companion.bssid = pins.bssid \
		WHERE wigle_companion.model || ' ' || wigle_companion.model_number NOT IN \
		(SELECT device FROM vulnwsc);"

# Outputs a .csv file based on OneShot report, with GPS coordinates added
# Replaces OneShot-GPS-Merger (https://github.com/eda-abec/OneShot-GPS-Merge)
# input:       none
# uses tables: oneshot, wigle
# output:      OneShot report with GPS columns appended
# TODO
#  - KML output
#  - unmatched networks output
#  - "wc -l" - header row
MERGED_FILE = stored_gps.csv
merge:
	@echo -n "Previously matched networks: "
	# not using simple 'wc -l' is to suppress errors with nonexistent file and improve formatting
	cat $(MERGED_FILE) 2> /dev/null | tail -n +3 -- | wc -l

	# add header
	echo "Date;BSSID;ESSID;WPS PIN;WPA PSK;CurrentLatitude;CurrentLongitude;RSSI;AuthMode" > $(MERGED_FILE)
	$(INTERPRETER) $(DB_FILE) -separator ";" \
		"SELECT oneshot.*, CurrentLatitude, CurrentLongitude, rssi, AuthMode FROM oneshot \
		INNER JOIN (SELECT * FROM wigle GROUP BY mac ORDER BY MIN(rssi)) AS wigle \
		ON oneshot.bssid = wigle.mac;" \
		>> $(MERGED_FILE)

	# print number of matched networks
	$(INTERPRETER) $(DB_FILE) \
		"SELECT 'Matched ' || COUNT(*) || ' (' || (COUNT(*) * 100 / (SELECT COUNT(*) FROM oneshot)) || '%) networks' FROM oneshot \
		INNER JOIN (SELECT * FROM wigle GROUP BY mac ORDER BY MIN(rssi)) AS wigle \
		ON oneshot.bssid = wigle.mac;"
	echo "Saved as $(MERGED_FILE)"

# Outputs a .csv file based on PINs, with GPS coordinates added
# Replaces OneShot-GPS-Merger (https://github.com/eda-abec/OneShot-GPS-Merge)
# input:       none
# uses tables: pins, wigle
# output:      OneShot report with GPS columns appended, with unapplicable columns empty
MERGED_PINS = stored_gps_pins.csv
merge_pins:
	@echo -n "Previously matched PINs: "
	# not using simple 'wc -l' is to suppress errors with nonexistent file and improve formatting
	cat $(MERGED_PINS) 2> /dev/null | tail -n +2 -- | wc -l

	# add header
	echo "Date;BSSID;ESSID;WPS PIN;WPA PSK;CurrentLatitude;CurrentLongitude;RSSI;AuthMode" > $(MERGED_PINS)
	$(INTERPRETER) $(DB_FILE) -separator ";" \
		"SELECT '', pins.bssid, ssid, pins.pin, '', CurrentLatitude, CurrentLongitude, rssi, AuthMode FROM pins \
		INNER JOIN (SELECT * FROM wigle GROUP BY mac ORDER BY MIN(rssi)) AS wigle \
		ON pins.bssid = wigle.mac;" \
		>> $(MERGED_PINS)

	# print number of matched PINs
	$(INTERPRETER) $(DB_FILE) \
		"SELECT 'Matched ' || COUNT(*) || ' (' || (COUNT(*) * 100 / (SELECT COUNT(*) FROM pins)) || '%) PINs' FROM pins \
		INNER JOIN (SELECT * FROM wigle GROUP BY mac ORDER BY MIN(rssi)) AS wigle \
		ON pins.bssid = wigle.mac;"
	echo "Saved as $(MERGED_PINS)"


#TODO
merge_kml:
	@echo "Not yet implemented"
	echo "import simplekml" | python3

# Prints all APs with given device model
# input:       ARG - device model, with SQL regex syntax
# uses tables: wigle_companion, wigle
# output:      CSV in WiGLE format
find_model:
	@# print WiGLE csv-compatible header
	echo "WigleWifi-1.4,appRelease=1,model=PC,release=1,device=PC,display=yes,board=desk,brand=new"
	echo "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type"

	$(INTERPRETER) $(DB_FILE) --separator ',' \
		"SELECT * FROM wigle \
		INNER JOIN wigle_companion ON wigle_companion.bssid = wigle.mac \
		WHERE $(MODEL_FORMAT) LIKE '$(ARG)';"

# Finds all coordinates where given network was spotted
# To be fed to Sniper (https://github.com/eda-abec/WiGLE-WiFi-Sniper)
# input:       ARG - SSID of network/s, with SQL regex syntax
# uses tables: wigle
# output:      CSV in WiGLE format
sniper:
	@# print WiGLE csv-compatible header
	echo "WigleWifi-1.4,appRelease=1,model=PC,release=1,device=PC,display=yes,board=desk,brand=new"
	echo "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type"

	$(INTERPRETER) --separator ',' $(DB_FILE) \
		"SELECT * FROM wigle \
		WHERE wigle.ssid LIKE '$(ARG)';"

# Prints statistics of collected data
# input:       none
# uses tables: oneshot, wigle_companion, wigle, vulnwsc
# output:      text report
# TODO
#  - option for MD format
#  - duplicates count
stats:
	@echo "OneShot"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Records:            ' \
		|| COUNT(*) FROM oneshot;"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Avg PSK length:     ' \
		|| ROUND(AVG(LENGTH([WPA PSK])), 3) || ' chars' \
		FROM oneshot WHERE LENGTH([WPA PSK]) > 0;"
	$(INTERPRETER) $(DB_FILE) "SELECT ' PSK same as PIN:    ' \
		|| COUNT(*) || ' times' FROM oneshot WHERE [WPS PIN] = [WPA PSK];"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Most common PIN:    ' \
		|| [WPS PIN] || ', ' || COUNT(*) || ' times' FROM oneshot \
		GROUP BY [WPS PIN] ORDER BY COUNT([WPS PIN]) DESC LIMIT 1;"
	# this value basically does not make any sense
	#$(INTERPRETER) $(DB_FILE) "SELECT ' Average PIN value:  ' \
	#	|| ROUND(AVG([WPS PIN]), 3) FROM oneshot;"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Open networks:      ' \
		|| COUNT(*) FROM oneshot WHERE [WPA PSK] = '';"
	$(INTERPRETER) $(DB_FILE) "SELECT ' 8-chars PSK:        ' \
		|| COUNT(*) || ' times' FROM oneshot WHERE LENGTH([WPA PSK]) = 8;"
	$(INTERPRETER) $(DB_FILE) "SELECT ' duplicated BSSIDs:  ' \
		|| COALESCE(SUM(DISTINCT cnt), 0) FROM \
		(SELECT COUNT(bssid) as cnt \
		FROM oneshot \
		GROUP BY bssid \
		HAVING COUNT(bssid) > 1)"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Most common device: ' \
		|| $(MODEL_FORMAT) || ', ' || COUNT(*) || ' times' FROM wigle_companion \
		INNER JOIN oneshot ON wigle_companion.bssid = oneshot.bssid \
		GROUP BY model, model_number ORDER BY COUNT(model) DESC LIMIT 1;"
	
	echo ""
	echo "WiGLE (WPS only)"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Records:            ' \
		|| COUNT(*) FROM wigle;"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Unique networks:    ' \
		|| COUNT(DISTINCT mac) || ' (~' || (COUNT(*) / (SELECT COUNT(DISTINCT mac))) || ' records per net)' FROM wigle;"
	
	$(INTERPRETER) $(DB_FILE) "SELECT ' Average signal:     ' \
		|| ROUND(AVG(rssi), 2) || ' dBm' FROM wigle;"
	#$(INTERPRETER) $(DB_FILE) "SELECT ' Average max signal: ' \
	#	|| ROUND(AVG(rssi), 2) || ' dBm' FROM wigle \
	#	GROUP BY mac ORDER BY MAX(rssi);"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Lowest signal:      ' \
		|| MAX(rssi) || ' dBm' FROM wigle;"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Highest signal:     ' \
		|| MIN(rssi) || ' dBm' FROM wigle;"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Signal < -60 dBm:   ' \
		|| COUNT(DISTINCT mac) || ' nets' FROM wigle \
		WHERE rssi < -60;"
	
	$(INTERPRETER) $(DB_FILE) "SELECT ' WPA2 networks:      ' \
		|| COUNT(DISTINCT mac) FROM wigle \
		WHERE AuthMode LIKE '%WPA2%';"
	$(INTERPRETER) $(DB_FILE) "SELECT ' WPA-only networks:  ' \
		|| COUNT(DISTINCT mac) FROM wigle \
		WHERE AuthMode LIKE '%WPA%' AND AuthMode NOT LIKE '%WPA2%';"
	$(INTERPRETER) $(DB_FILE) "SELECT ' WEP networks:       ' \
		|| COUNT(DISTINCT mac) FROM wigle \
		WHERE AuthMode LIKE '%WEP%';"
	
	echo ""
	echo "wigle_companion"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Records:            ' \
		|| COUNT(*) FROM wigle_companion;"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Recorded models:    ' \
		|| COUNT(DISTINCT $(MODEL_FORMAT)) FROM wigle_companion;"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Vulnerable nets:    ' \
		|| COUNT(*) || ' (' || (COUNT(*)* 100 / (SELECT COUNT(*) FROM wigle_companion)) || '%)' FROM wigle_companion \
		WHERE $(MODEL_FORMAT) IN \
		(SELECT device FROM vulnwsc);"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Most common device: ' \
		|| $(MODEL_FORMAT) || ', ' || COUNT(model and model_number) || ' times' FROM wigle_companion \
		GROUP BY model, model_number ORDER BY COUNT(model) DESC LIMIT 1;"
	
	echo ""
	echo "vulnwsc"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Vulnerable models:  ' \
		|| COUNT(*) FROM vulnwsc;"

	echo ""
	echo "PIN-only networks"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Records:            ' \
		|| COUNT(*) FROM pins;"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Most common PIN:    ' \
		|| pin || ', ' || COUNT(*) || ' times' FROM pins \
		GROUP BY pin ORDER BY COUNT(pin) DESC LIMIT 1;"
	$(INTERPRETER) $(DB_FILE) "SELECT ' Average PIN value:  ' \
	|| ROUND(AVG(pin), 3) FROM pins;"

# Prints statistics of models of networks in OneShot report
# input:       MODEL_FORMAT, ORDER - default DESC, other possible value ASC
# uses tables: oneshot, wigle_companion
# output:      list of models sorted by occurrence count
stats_oneshot_devices:
	@$(INTERPRETER) $(DB_FILE) "SELECT COUNT(DISTINCT oneshot.bssid) || ': ' || $(MODEL_FORMAT) FROM wigle_companion \
		INNER JOIN oneshot ON wigle_companion.bssid = oneshot.bssid \
		GROUP BY model, model_number ORDER BY COUNT(model) $(ORDER);"
	
	echo ""
	$(INTERPRETER) $(DB_FILE) "SELECT COUNT(DISTINCT bssid) || ' unknown' FROM oneshot \
		WHERE bssid NOT IN (SELECT bssid FROM wigle_companion);"

# Prints statistics of models of networks from wigle_companion
# input:       MODEL_FORMAT, ORDER - default DESC, other possible value ASC
# uses tables: wigle_companion
# output:      list of models sorted by occurrence count
stats_comp_devices:
	@$(INTERPRETER) $(DB_FILE) "SELECT COUNT(DISTINCT bssid) || ': ' || $(MODEL_FORMAT) FROM wigle_companion \
		GROUP BY model, model_number ORDER BY COUNT(model) $(ORDER);"

# Prints statistics of how covered are rows of one table in another
# input:       none
# uses tables: oneshot, wigle_companion, wigle
# output:      numbers of networks in particular table that are not in other table
#TODO
#  - percents
#  - Venn diagram would be great
correlation:
	@$(INTERPRETER) $(DB_FILE) "SELECT COUNT(DISTINCT bssid) || ' in OneShot, but not in wigle_companion' FROM oneshot \
		WHERE bssid NOT IN (SELECT bssid FROM wigle_companion);"
	
	$(INTERPRETER) $(DB_FILE) "SELECT COUNT(DISTINCT bssid) || ' in OneShot, but not in WiGLE' FROM oneshot \
		WHERE bssid NOT IN (SELECT mac FROM wigle);"
	
	$(INTERPRETER) $(DB_FILE) "SELECT COUNT(DISTINCT bssid) || ' in wigle_companion, but not in WiGLE' FROM wigle_companion \
		WHERE bssid NOT IN (SELECT mac FROM wigle);"

	$(INTERPRETER) $(DB_FILE) "SELECT COUNT(DISTINCT bssid) || ' in PINs, but not in wigle_companion' FROM pins \
		WHERE bssid NOT IN (SELECT bssid FROM wigle_companion);"

	$(INTERPRETER) $(DB_FILE) "SELECT COUNT(DISTINCT bssid) || ' in PINs, but not in WiGLE' FROM pins \
		WHERE bssid NOT IN (SELECT mac FROM wigle);"




## data insertion rules

# TODO
#  - work with dates as dates
#  - work with PINs as numbers

# Shortcut for importing everything
import: import_oneshot import_wigle_csv import_vulnwsc import_wigle_companion \
	pins_to_csv import_pins

# Imports report from OneShot to the DB to work with
# input:       ONESHOT_FILE - defaults to 'stored.csv'
# uses tables: oneshot
# output:      none
ONESHOT_FILE = stored.csv
import_oneshot:
	@echo "Importing OneShot"
	$(INTERPRETER) $(DB_FILE) <<'END_SQL'
		DROP TABLE IF EXISTS oneshot;
		.mode csv \n
		.separator ';' \n
		.import $(ONESHOT_FILE) oneshot
		END_SQL

# Imports observations from WiGLE to the DB to work with
# input:       WIGLE_FILE - name of csv file(s), supports shell wildcards
# uses tables: wigle
# output:      none
WIGLE_CSV_FILE = wigle/WigleWifi_*.csv
import_wigle_csv:
	@echo "Importing" $$(ls $(WIGLE_CSV_FILE) | wc -l) "WiGLE file(s) from csv"

	$(INTERPRETER) $(DB_FILE) "DROP TABLE IF EXISTS wigle;"

	for file in $(WIGLE_CSV_FILE); do
		echo " " $$file "..."
		# first, escape newlines, then remove 1st line
		sed 's/"/\\"/g' $$file | tail -n +2 -- > .WigleWifi_tmp.csv

		$(INTERPRETER) $(DB_FILE) <<'END_SQL'
			.mode csv \n
			.separator ',' \n
			.import .WigleWifi_tmp.csv wigle
			END_SQL
	done
	
	rm .WigleWifi_tmp.csv


	# filter non-WPS networks
	$(INTERPRETER) $(DB_FILE) \
		"DELETE FROM wigle WHERE AuthMode not like '%WPS%';"
	
	# unify MAC addresses to uppercase
	$(INTERPRETER) $(DB_FILE) \
		"UPDATE wigle SET mac = UPPER(mac);"

#!!! TODO not working yet
# Imports observations from WiGLE to the DB to work with
# input:       WIGLE_FILE - defaults to 'backup.sqlite'
# uses tables: wigle
# output:      none
# TODO
#   - import with wildcard in name
WIGLE_FILE = backup.sqlite
import_wigle:
	@echo "Not yet implemented"
	@echo "Importing WiGLE"
	$(INTERPRETER) $(WIGLE_FILE) <<'END_SQL'
		ATTACH "$(DB_FILE)" AS SQLShot;
		DROP TABLE IF EXISTS SQLShot.wigle;
		CREATE TABLE SQLShot.wigle AS SELECT * FROM main.network;
		END_SQL

	# filter non-WPS networks
	$(INTERPRETER) $(DB_FILE) \
		"DELETE FROM wigle WHERE AuthMode not like '%WPS%';"

	# unify MAC addresses to uppercase
	$(INTERPRETER) $(DB_FILE) \
		"UPDATE wigle SET mac = UPPER(mac);"

# Imports list of vulnerable devices to the DB to work with
# input:       VULNWSC_FILE - defaults to 'vulnwsc.txt'
# uses tables: vulnwsc
# output:      none
VULNWSC_FILE = vulnwsc.txt
import_vulnwsc:
	@echo "Importing vulnwsc"
	$(INTERPRETER) $(DB_FILE) <<'END_SQL'
		DROP TABLE IF EXISTS vulnwsc;
		CREATE TABLE vulnwsc (device TEXT);
		.mode csv \n
		.import $(VULNWSC_FILE) vulnwsc
		END_SQL

# Imports wigle_companion devices to the DB to work with
# input:       COMPANION_FILE - defaults to 'networks.db'
# uses tables: wigle_companion
# output:      none
COMPANION_FILE = networks.db
import_wigle_companion:
	@echo "Importing wigle_companion"
	$(INTERPRETER) $(COMPANION_FILE) <<'END_SQL'
		ATTACH "$(DB_FILE)" AS SQLShot;
		DROP TABLE IF EXISTS SQLShot.wigle_companion;
		CREATE TABLE SQLShot.wigle_companion AS SELECT * FROM main.network;
		END_SQL

# alias
import_companion: import_wigle_companion

# Parses a folder of PINs from Pixie to a CSV file
# input:       PINS_CSV - name of the temporary file
# uses tables: none
# output:      pins.csv
PINS_CSV = pins.csv
pins_to_csv:
	@echo "Parsing PINs"
	echo "BSSID;PIN" > $(PINS_CSV)    # header
	for file in pins/*; do
		echo -n "$$file" |		# BSSID
			sed 's/^pins\///' | \
			sed 's/.run//'    | \
			# add colons into the MAC
			sed 's/..\B/&:/g' \
			>> $(PINS_CSV)
		echo -n ";" >> $(PINS_CSV)	# separator
		cat "$$file" >> $(PINS_CSV)     # PIN
		echo "" >> $(PINS_CSV)          # newline
	done

# Imports PINs from a CSV file generated by pins_to_csv
# input:       PINS_CSV - name of the temporary file
# uses tables: pins
# output:      none
import_pins:
	@echo "Importing PINs"
	$(INTERPRETER) $(DB_FILE) <<'END_SQL'
		DROP TABLE IF EXISTS pins;
		.mode csv \n
		.separator ';' \n
		.import $(PINS_CSV) pins
		END_SQL
