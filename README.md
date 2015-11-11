# AndroBugs Framework

AndroBugs Framework is an Android vulnerability analysis system that helps developers or hackers find potential security vulnerabilities in Android applications. 
No splendid GUI interface, but the most efficient (less than 2 minutes per scan in average) and more accurate.

Version: 1.0.0

####Features:####

- Find security vulnerabilities in an Android app
- Check if the code is missing best practices
- Check dangerous shell commands (e.g. “su”)
- Collect Information from millions of apps
- Check the app’s security protection (marked as ```<Hacker>```, designed for app repackaging hacking)


##Author

- Yu-Cheng Lin  (androbugs.framework at gmail.com, @AndroBugs)

## Steup Steps and Usage for Windows

**Easy to use for Android developers or hackers on Microsoft Windows: (a) No need to install Python 2.7 (b) No need to install any 3rd-party library (c) No need to install AndroBugs Framework**

1. mkdir C:\AndroBugs_Framework
2. cd C:\AndroBugs_Framework
3. Unzip the latest Windows version of AndroBugs Framework from [Windows releases](https://github.com/AndroBugs/AndroBugs_Framework/releases)
4. Go to Computer->System Properties->Advanced->Environment Variables. Add "C:\AndroBugs_Framework" to the "Path" variable
5. ```androbugs.exe -h```
6. ```androbugs.exe -f [APK file]```

## Massive Analysis Tool Steup Steps and Usage for Windows
1. Complete the *Steup Steps and Usage for Windows* first
2. Install the Windows version of MongoDB (https://www.mongodb.org/downloads)
3. Install [PyMongo library](http://api.mongodb.org/python/current/installation.html)
4. Config your own MongoDB settings: C:\AndroBugs_Framework\androbugs-db.cfg
5. Choose your preferred MongoDB management tool (http://mongodb-tools.com/)
6. ```AndroBugs_MassiveAnalysis.exe -h```
  - Example: ```AndroBugs_MassiveAnalysis.exe -b 20151112 -t BlackHat -d .\All_Your_Apps\ -o .\Massive_Analysis_Reports```
7. ```AndroBugs_ReportByVectorKey.exe -h```
  - Example: ```AndroBugs_ReportByVectorKey.exe -v WEBVIEW_RCE -l Critical -b 20151112 -t BlackHat```

## Usage for Unix/Linux

####To run the AndroBugs Framework:####

```
python androbugs.py -f [APK file]
```

####To check the usage:####

```
python androbugs.py -h
```

## Usage of Massive Analysis Tools for Unix/Linux

**Prerequisite: Setup MongoDB and config your own MongoDB settings in "androbugs-db.cfg"**

####To run the massive analysis for AndroBugs Framework:####

```
python AndroBugs_MassiveAnalysis.py -b [Your_Analysis_Number] -t [Your_Analysis_Tag] -d [APKs input directory] -o [Report output directory]
```
 
Example:
```
python AndroBugs_MassiveAnalysis.py -b 20151112 -t BlackHat -d ~/All_Your_Apps/ -o ~/Massive_Analysis_Reports
```


####To get the summary report and all the vectors of massive analysis:####

```
python AndroBugs_ReportSummary.py -m massive -b [Your_Analysis_Number] -t [Your_Analysis_Tag]
```

Example:
```
python AndroBugs_ReportSummary.py -m massive -b 20151112 -t BlackHat
```


####To list the potentially vulnerable apps by Vector ID and Severity Level (Log Level):####

```
python AndroBugs_ReportByVectorKey.py -v [Vector ID] -l [Log Level] -b [Your_Analysis_Number] -t [Your_Analysis_Tag]
python AndroBugs_ReportByVectorKey.py -v [Vector ID] -l [Log Level] -b [Your_Analysis_Number] -t [Your_Analysis_Tag] -a
```

Example:
```
python AndroBugs_ReportByVectorKey.py -v WEBVIEW_RCE -l Critical -b 20151112 -t BlackHat
python AndroBugs_ReportByVectorKey.py -v WEBVIEW_RCE -l Critical -b 20151112 -t BlackHat -a
```

![AndroBugs_ReportSummary.py](http://www.androbugs.com/images/v1.0.0/MassiveAnalysisTool2.png)

![AndroBugs_ReportByVectorKey.py](http://www.androbugs.com/images/v1.0.0/MassiveAnalysisTool1.png)

##Requirements

- Python 2.7.x (DO NOT USE Python 3.X)
- [PyMongo library](http://api.mongodb.org/python/current/installation.html) (If you want to use the massive analysis tool)

##Licenses

* AndroBugs Framework is under the license of [GNU GPL v3.0](http://www.gnu.org/licenses/gpl-3.0.txt)

