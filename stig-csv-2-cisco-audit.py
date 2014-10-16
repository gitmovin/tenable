#!/usr/bin/python

import csv
import sys

print "<check_type:\"Cisco\">"

csvfile = open(sys.argv[1],'rb')
csvreader = csv.reader(csvfile)

row_num = 0
for row in csvreader:
  vuln_id = ""
  severity = ""
  rule_id = ""
  group_id = ""
  rule_title = ""
  discussion = ""
  ia_controls = ""
  check_content = ""
  fix_text = ""
  reference = ""

  if row_num == 0:
    header = row
  else:
    col_num = 0
    for col in row:
      #print '%s - %-8s: %s' % (col_num,header[col_num], col)
      if col_num == 0:
        vuln_id = col
      elif col_num == 1:
        if col == "high":
          severity = "CAT I"
        elif col == "medium":
          severity = "CAT II"
        elif col == "low":
          severity = "CAT III"
        else:
          severity = "UNKNOWN"
      elif col_num == 2:
        group_title = col
      elif col_num == 3:
        rule_id = col
      elif col_num == 4:
        stig_id = col
      elif col_num == 5:
        rule_title = col
      elif col_num == 6:
        discussion = col
      elif col_num == 7:
        ia_controls = ""
      elif col_num == 8:
        check_content = col
      elif col_num == 9:
        fix_text = col
      elif col_num == 21:
        reference = col
      #print "  type         : CONFIG_CHECK
      #print "description  : "VERS TEST"
      #print "info         : "Check if version is later than 12.2(8)T."
      #print  "info		: "ref. https://www.cisecurity.org/tools2/cisco/CIS_Cisco_IOS_Benchmark_v2.2.pdf, page 9."
      col_num += 1
    print "<item>"
    print "  type        : CONFIG_CHECK"
    print "  description : " + stig_id + " - " + rule_title
    print "  info        : \"VULN ID - " + vuln_id + "\""
    print "  info        : \"Severity - " + severity + "\""
    print "  info        : \"Group Title - " + group_id + "\""
    print "  info        : \"Rule ID - " + rule_id + "\""
    print "  info        : \"STIG ID - " + stig_id + "\""
    print "  info        : \"Rule Title - " + rule_title + "\""
    print "  info        : \"Discussion - " + discussion + "\""
    print "  info        : \"IA Controls - " + ia_controls + "\""
    print "  info        : \"Check Content - " + check_content + "\""
    print "  solution    : \"Fix Text - " + fix_text + "\""
    print "  reference   : \"\""
    print "  item        : \"\""
    print "  regex       : \"\""
    print "  see_also    : \"" + reference + "\""
    print "</item>\n"
  row_num += 1
csvfile.close()

print "</check_type>"

