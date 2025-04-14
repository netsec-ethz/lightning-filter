#!/usr/bin/env python3
import os
from plumbum import local
from acceptance.common import scion

def main():
	gen_dir = local.path(os.path.dirname(__file__) + "/tmp")
	isd_ases = scion.ASList.load(gen_dir / "as_list.yml").all

	for isd_as in isd_ases:
		conf_dir = gen_dir / ("AS" + isd_as.as_file_fmt())
		scion.update_toml({
			"drkey": {
				"level1_db": {
					"connection": "gen-cache/cs%s-1.drkey_level1.db" % isd_as.file_fmt(),
				},
				"secret_value_db": {
					"connection": "gen-cache/cs%s-1.secret_value.db" % isd_as.file_fmt()
				}
			}
		}, conf_dir // "cs*-1.toml")
		scion.update_toml({
			"drkey_level2_db": {
				"connection": "gen-cache/sd%s.drkey_level2.db" % isd_as.file_fmt()
			}
		}, conf_dir // "sd.toml")

if __name__ == "__main__":
	main()
