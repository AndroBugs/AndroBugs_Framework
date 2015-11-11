from pymongo import MongoClient
import argparse
import sys
from datetime import datetime
from ConfigParser import SafeConfigParser
import platform
import os

"""
	Example usage:
		python AndroBugs_ReportByVectorKey.py -v [vector_name] -m [mode] -l [Log level]
		python AndroBugs_ReportByVectorKey.py -v WEBVIEW_RCE -m massive -l Critical

	Example output:
		Vector: WEBVIEW_RCE
		----------------------------------------------------------------------------------------------------
		Critical (Total: 16):
		     (package name 1)
		     (package name 2)
		     (package name 3)
		     ...
"""

def parseArgument():
	parser = argparse.ArgumentParser(description='AndroBugs Framework: Android APK Vulnerability Reporter by Vector Name')
	
	parser.add_argument("-v", "--vector", help="Vector name", type=str, required=True)
	parser.add_argument("-b", "--analyze_engine_build", help="Analysis build number.", type=int, required=False, default=None)
	parser.add_argument("-m", "--analyze_mode", help="Specify \"single\" or \"massive\"", type=str, required=False)
	parser.add_argument("-t", "--analyze_tag", help="Analysis tag to uniquely distinguish this time of analysis.", type=str, required=False, default=None)
	parser.add_argument("-l", "--log_level", help="Specify \"Critical\", \"Warning\", \"Notice\" or \"Info\"", type=str, required=True)
	parser.add_argument("-a", "--ALL", help="Specify this argument if you want to see the apps for all the log level.", action="store_true")

	args = parser.parse_args()
	return args

def __sort_by_level(data):
	key = data[0]
	try :
		if key == "Critical":
			return 5
		elif key == "Warning":
			return 4
		elif key == "Notice":
			return 3
		elif key == "Info":
			return 2
		else:
			return 1
	except KeyError :
		return 1

args = parseArgument()

print("## AndroBugs Framework: Android APK Vulnerability Reporter by Vector Name ##")
print

if platform.system().lower() == "windows" :
	import sys
	db_config_file = os.path.join(os.path.dirname(sys.executable), 'androbugs-db.cfg')
else :
	db_config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'androbugs-db.cfg')

if not os.path.isfile(db_config_file) :
	print("[ERROR] AndroBugs Framework DB config file not found: " + db_config_file)
	traceback.print_exc()

configParser = SafeConfigParser()
configParser.read(db_config_file)

MongoDB_Hostname = configParser.get('DB_Config', 'MongoDB_Hostname')
MongoDB_Port = configParser.getint('DB_Config', 'MongoDB_Port')
MongoDB_Database = configParser.get('DB_Config', 'MongoDB_Database')

Collection_Analyze_Success_Results_FastSearch = configParser.get('DB_Collections', 'Collection_Analyze_Success_Results_FastSearch')

client = MongoClient(MongoDB_Hostname, MongoDB_Port)

db = client[MongoDB_Database]	# Name is case-sensitive

collection_Analyze_Success_Results_FastSearch = db[Collection_Analyze_Success_Results_FastSearch]		# Name is case-sensitive

query_condition = dict()
if args.vector :
	query_condition["vector"] = args.vector
if args.analyze_engine_build :
	query_condition["analyze_engine_build"] = args.analyze_engine_build
if args.analyze_mode :
	query_condition["analyze_mode"] = args.analyze_mode
if args.analyze_tag :
	query_condition["analyze_tag"] = args.analyze_tag
if not args.ALL :
	if args.log_level :
		query_condition["level"] = args.log_level


# ------------------------------------------------------------------------------------

vector_to_level_count_list = {}

total_count = 0

vector_container = { "Critical":[], "Warning":[], "Notice":[], "Info":[] }

if args.log_level not in vector_container :
	print("Log level must be: \"Critical\", \"Warning\", \"Notice\" or \"Info\"")
	sys.exit()


print("Vector: %s" % (args.vector))

print('-' * 80)

time_start = datetime.now()

query_result = collection_Analyze_Success_Results_FastSearch.find(query_condition)

time_end = datetime.now()

if args.ALL :

	for report in query_result :
		total_count = total_count + 1

		try :
			package_name = report["package_name"]
			level = report["level"]

			package_version_code = None
			if "package_version_code" in report :
				package_version_code = report["package_version_code"]

			if level in vector_container :
				vector_container[level].append( (package_name, package_version_code))

		except KeyError :
			pass

else :

	for report in query_result :
		total_count = total_count + 1

		try :
			package_name = report["package_name"]

			package_version_code = None
			if "package_version_code" in report :
				package_version_code = report["package_version_code"]

			vector_container[args.log_level].append( (package_name, package_version_code) )

		except KeyError :
			pass

value_list = vector_container[args.log_level]

print(args.log_level + " (Total: " + str(len(value_list)) + "):")

if value_list :
	for package_name, package_version_code in value_list :
		if package_version_code is not None :
			print("     %-45s (version code: %d)" % (package_name, package_version_code))
		else :
			print("     %-45s" % package_name)
else :
	print("     Not found.")	
print

if args.ALL :
	for log_level, value_list in sorted(vector_container.items(), key=__sort_by_level, reverse=True) :
		if log_level != args.log_level : #prevent from printing duplicated ones
			print(log_level + " (Total: " + str(len(value_list)) + "):")
		
			if value_list :
				for package_name, package_version_code in value_list :
					if package_version_code is not None :
						print("     %-45s (version code: %d)" % (package_name, package_version_code))
					else :
						print("     %-45s" % package_name)
			else :
				print("     Not found.")	

			print

print('-' * 80)

# ------------------------------------------------------------------------------------	

time_execution = time_end - time_start

print("Query result count: %d" % (total_count))
print("Execution time: %f secs" % (time_execution.total_seconds()))
print

