#!/usr/bin/env python3
import os
import sys
import json
import datetime
from math import floor
import termplotlib as tpl
from rich import print
from rich.table import Table
from rich.align import Align
from rich.layout import Layout
from rich.console import Console
from rich.panel import Panel
from numpy import histogram,percentile
from collections import OrderedDict
from pprint import pprint

class PhylumReport():
    def __init__(self):
        self.layout = Layout()
        self.console = Console()
        self.console.clear()

    def setup_layout(self):
        self.layout.split(Layout(name='A'),Layout(name='B'))
        self.layout['A'].size = 10
        self.layout['A'].update(self.build_stats_panel())
        self.layout['B'].split_row(Layout(name='C'),Layout(name='D'))
        self.layout['C'].split(Layout(name='E'),Layout(name='F'))
        self.layout['E'].update(Align.center(self.build_ps_histogram()))
        self.layout['D'].update(Align.center(self.build_top_offenders_panel()))
        self.layout['F'].update(Align.center(self.build_vuln_table()))
        #self.layout['AA'].update(self.build_stats_panel())
        self.console.print(self.layout)
        return


    def read_cli_response_json(self, input_stream):
        self.jsondata = json.loads(input_stream)
        return

    def build_vuln_table(self):
        temp_vuln_table = dict()
        all_crit    = 0
        all_high    = 0
        all_med     = 0
        all_low     = 0
        all_total   = 0
        for pkg in self.jsondata.get('packages'):
            if len(pkg.get('vulnerabilities')) > 0:
                pkg_name = pkg.get('name')
                crit = 0
                high = 0
                med = 0
                low = 0
                total = 0
                for vuln in pkg.get('vulnerabilities'):
                    severity = vuln.get('base_severity').lower()
                    total += 1
                    if severity == 'high':
                        high += 1
                    elif severity == 'critical':
                        crit += 1
                    elif severity == 'medium':
                        med +=1
                    elif severity == 'low':
                        low +=1

                if not temp_vuln_table.get(pkg_name):
                    temp_vuln_table[pkg_name] = [crit,high,med,low,total]


        self.vuln_table = Table(show_header=True, header_style="Bold Magenta", show_footer=True)
        self.vuln_table.add_column('Package Name', width=25, footer="Total")
        self.vuln_table.add_column('Critical')
        self.vuln_table.add_column('High')
        self.vuln_table.add_column('Medium')
        self.vuln_table.add_column('Low')
        self.vuln_table.add_column('Total')
        for pkg_name,sevs in temp_vuln_table.items():
            self.vuln_table.add_row(pkg_name, str(sevs[0]), str(sevs[1]), str(sevs[2]), str(sevs[3]), str(sevs[4]))
            all_crit    += sevs[0]
            all_high    += sevs[1]
            all_med     += sevs[2]
            all_low     += sevs[3]
            all_total   += sevs[4]

        self.vuln_table.columns[1].footer = str(all_crit)
        self.vuln_table.columns[2].footer = str(all_high)
        self.vuln_table.columns[3].footer = str(all_med)
        self.vuln_table.columns[4].footer = str(all_low)
        self.vuln_table.columns[5].footer = str(all_total)

        panel_vulntable = Panel(self.vuln_table, title="Software Vulnerabilities by Package")
        return panel_vulntable


    def build_ps_histogram(self):
        package_scores = list()
        for pkg in self.jsondata.get('packages'):
            score = pkg.get('package_score')
            score = score * 100
            final_score = f"{score:3.2f}"
            final_score = float(final_score)
            #  package_scores.append(pkg.get('package_score') * 100)
            package_scores.append(final_score)

        newedges = [x for x in range(0,110,10)]
        counts, binedges = histogram(package_scores, bins=newedges)
        fig = tpl.figure()
        fig.hist(counts,newedges, orientation='horizontal', force_ascii=False)
        fig_str = fig.get_string()
        fig_str = self.format_figure(fig_str)
        #self.layout['left'].update(fig_str)
        panel_ps_histogram = Panel(fig_str, title="Histogram of Package Scores")
        return panel_ps_histogram

    def build_stats_panel(self):
        num_packages = str(len(self.jsondata.get('packages')))
        job_id = self.jsondata.get('id')
        started_timestamp = self.jsondata.get('created_at')
        #updated_timestamp = self.jsondata.get('last_updated')
        started_date_time = str(datetime.datetime.fromtimestamp(started_timestamp/1000).strftime('%c'))
        #updated_date_time = str(datetime.datetime.fromtimestamp(updated_timestamp/1000).strftime('%c'))

        #self.stats_table = Table(show_header=False)
        self.stats_table = Table.grid()
        self.stats_table.add_column()
        self.stats_table.add_column()
        self.stats_table.add_column()
        self.stats_table.add_row("", ' ', ' ')
        self.stats_table.add_row("[b]Num Packages", ' ', num_packages)
        self.stats_table.add_row("[b]Started Time", ' ', started_date_time)
        #self.stats_table.add_row("[b]Completed Time", updated_date_time)
        self.stats_table.add_row("[b]Job ID",' ', job_id)

        panel_stats = Panel(self.stats_table, title="Phylum Report")
        return panel_stats

    def build_top_offenders_panel(self):
        psd = dict()
        # get all the packages and package_score values
        for pkg in self.jsondata.get('packages'):
            name = pkg['name']
            score = pkg['package_score']
            #psd[name] = score
            #h_count = len(pkg['heuristics'].keys())
            psd[name] = score

        # sort them by package_score
        spsd = dict(sorted(psd.items(), key=lambda item: item[1]))
        # get a list of the top (worst) 50
        top25_offenders = list(spsd.items())[:50]

        # get the why
        result = OrderedDict()
        for x in top25_offenders:
            name,score = x
            result[name] = dict()
            result[name]['score'] = score
            for pkg in self.jsondata.get('packages'):
                if pkg['name'] == name:
                    vulns = pkg['vulnerabilities'] # list
                    result[name]['vuln_count'] = pkg.get('num_vulnerabilities')
                    #TODO: add package_score to vulnerability table
                    heur = pkg['heuristics'] # dict
                    min_hscore = 1
                    min_hname = "blah"
                    for hname,hval in heur.items():
                        hscore = hval.get('score') # might need to get raw_score?
                        if hscore < min_hscore:
                            min_hscore = hscore
                            min_hname = hname
                    result[name]['heur_min_name'] = min_hname
                    result[name]['heur_min_score'] = min_hscore

        self.offenders_table = Table(show_header=True)
        self.offenders_table.add_column('Package Name', width=30)
        self.offenders_table.add_column('Score', width=6)
        self.offenders_table.add_column('# Vulns', width=6)
        self.offenders_table.add_column('Min Heur Name', width=12)
        self.offenders_table.add_column('Min Heur Score', width=6)

        for name, val in result.items():
            adj_score = (val.get('score') * 100)
            adj_score = f"{adj_score:3.0f}"
            adj_min_score = (val.get('heur_min_score') * 100)
            adj_min_score = f"{adj_min_score:3.0f}"
            self.offenders_table.add_row(
                name,
                #str(val.get('score')),
                str(adj_score),
                str(val.get('vuln_count')),
                str(val.get('heur_min_name')),
                #str(val.get('heur_min_score')),
                str(adj_min_score),
            )

        offenders_panel = Panel(self.offenders_table, title="Worst Packages by Score")

        return offenders_panel


    def format_figure(self, fig_str):
        fig_str = fig_str.replace('+0.00e+00 - +1.00e+01',' 0 - 10 ')
        fig_str = fig_str.replace('+1.00e+01 - +2.00e+01','10 - 20 ')
        fig_str = fig_str.replace('+2.00e+01 - +3.00e+01','20 - 30 ')
        fig_str = fig_str.replace('+3.00e+01 - +4.00e+01','30 - 40 ')
        fig_str = fig_str.replace('+4.00e+01 - +5.00e+01','40 - 50 ')
        fig_str = fig_str.replace('+5.00e+01 - +6.00e+01','50 - 60 ')
        fig_str = fig_str.replace('+6.00e+01 - +7.00e+01','60 - 70 ')
        fig_str = fig_str.replace('+7.00e+01 - +8.00e+01','70 - 80 ')
        fig_str = fig_str.replace('+8.00e+01 - +9.00e+01','80 - 90 ')
        fig_str = fig_str.replace('+9.00e+01 - +1.00e+02','90 - 100')
        fig_str = "Score     Count\n" + fig_str
        return fig_str


if __name__ == "__main__":
    pr = PhylumReport()

    try:
        input_filename = sys.argv[1]
    except IndexError:
        message = 'requires filename as argument'
        raise IndexError(message)

    input_data = open(input_filename,'r').read()

    pr.read_cli_response_json(input_data)
    pr.setup_layout()
