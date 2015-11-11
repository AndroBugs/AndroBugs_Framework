from pymongo import MongoClient
import argparse
import sys
from ConfigParser import SafeConfigParser
import platform
import os

ANALYZE_MODE_SINGLE = "single"
ANALYZE_MODE_MASSIVE = "massive"

def parseArgument():
	parser = argparse.ArgumentParser(description='AndroBugs Framework: Android APK Vulnerability Summary Reporter (Parameter Condition: and)')
	parser.add_argument("-m", "--analyze_mode", help="Specify \"single\" or \"massive\"", type=str, required=True)
	parser.add_argument("-b", "--analyze_engine_build", help="Analysis build number.", type=int, required=False, default=None)
	parser.add_argument("-t", "--analyze_tag", help="Analysis tag to uniquely distinguish this time of analysis.", type=str, required=False, default=None)
	parser.add_argument("-s", "--analyze_status", help="\"success\", \"fail\", or \"all\"(default)", type=str, required=False, default=None)
	args = parser.parse_args()
	return args

args = parseArgument()

print("## AndroBugs Framework: Android APK Vulnerability Summary Reporter ##")
print

if platform.system().lower() == "windows" :
	import sys
	db_config_file = os.path.join(os.path.dirname(sys.executable), 'androbugs-db.cfg')
	print("[Notice] The output format is not good in Windows console")
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

Collection_Analyze_Result = configParser.get('DB_Collections', 'Collection_Analyze_Result')

client = MongoClient(MongoDB_Hostname, MongoDB_Port)

db = client[MongoDB_Database]	# Name is case-sensitive

collection_AppInfo = db[Collection_Analyze_Result]		# Name is case-sensitive
# collection_AnalyzeResults = db['AnalyzeSuccessResults']

query_condition = dict()
if args.analyze_mode :
	query_condition["analyze_mode"] = args.analyze_mode

if args.analyze_engine_build :
	query_condition["analyze_engine_build"] = args.analyze_engine_build

if args.analyze_tag :
	query_condition["analyze_tag"] = args.analyze_tag

if args.analyze_status :
	if args.analyze_status != "all" :
		query_condition["analyze_status"] = args.analyze_status

# ------------------------------------------------------------------------------------

vector_to_level_count_list = {}

count_success = 0
count_fail = 0
total_count = 0

for report in collection_AppInfo.find(query_condition) :
	if (report["analyze_status"] == "success") :
		count_success = count_success + 1
	elif (report["analyze_status"] == "fail") :
		count_fail = count_fail + 1

	if "details" in report :
		details = report["details"]
		for key, value in details.items() :
			if key not in vector_to_level_count_list :
				vector_to_level_count_list[key] = { "Critical":0, "Warning":0, "Notice":0, "Info":0 }
			level_tag = value["level"]

			vector_to_level_count_list[key][level_tag] = vector_to_level_count_list[key][level_tag] + 1

total_count = count_success + count_fail

print("%50s   %9s %9s %9s %9s %9s %17s %14s %14s %14s %17s" % ("Vector Name",
 	"Critical", "Warning", "Notice", "Info", "Total", 
	"% of Critical", "% of Warning", "% of Notice", "% of Info", "% of Non-Info"))
print('-' * 190)

if total_count == 0 :
	print("No Data.")
else :
	for key, level_count_list in sorted(vector_to_level_count_list.items()) :
		if count_success == 0 :
			print("%50s : %9s %9s %9s %9s %9s %16.2f%% %13.2f%% %13.2f%% %13.2f%% %16.2f%%" % (
				key, 
				level_count_list["Critical"], level_count_list["Warning"], level_count_list["Notice"], level_count_list["Info"], 
				count_success,
				0, 0, 0, 0, 0
				))
		else :
			print("%50s : %9s %9s %9s %9s %9s %16.2f%% %13.2f%% %13.2f%% %13.2f%% %16.2f%%" % (
				key, 
				level_count_list["Critical"], level_count_list["Warning"], level_count_list["Notice"], level_count_list["Info"], 
				count_success,
				(level_count_list["Critical"]/float(count_success)*100), (level_count_list["Warning"]/float(count_success)*100), 
				(level_count_list["Notice"]/float(count_success)*100), (level_count_list["Info"]/float(count_success)*100),
				((1-(level_count_list["Info"]/float(count_success)))*100)
				))
print('-' * 190)

# ------------------------------------------------------------------------------------	

count_total = count_success + count_fail

if (count_total > 0) :
	print("Total(Success + Fail to analyze) APKs: %d;  Success to analyze APKs: %d (%.2f%%);  Fail to analyze APKs: %d (%.2f%%)" % (
			count_total, count_success, ((count_success / float(count_total)) * 100 ), count_fail, ((count_fail / float(count_total)) * 100 )
		 ))

print
