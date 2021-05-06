# -*- coding: utf-8 -*-
# Copyright (C) 2017-2021 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
from datetime import date, timedelta
from terminaltables import AsciiTable


def check_args(args):
    len_args = len(args.script) - 1
    if len_args < 2:
        message = """
        This script will display all vulnerabilities from the hosts of the
        reports in a given month!
        It needs two parameters after the script name.
        First one is the month and second one is the year.
        Both parameters are plain numbers, so no text.
        Explicitly made for GOS 4.X.

        1. <month>  -- month of the monthly report
        2. <year>   -- year of the monthly report

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/monthly-report2.gmp.py 05 2019
        """
        print(message)
        sys.exit()


def print_reports(gmp, from_date, to_date):
    asset_filter = "rows=-1 and modified>{0} and modified<{1}".format(
        from_date.isoformat(), to_date.isoformat()
    )

    assets_xml = gmp.get_assets(
        asset_type=gmp.types.AssetType.HOST, filter=asset_filter
    )
    
    sum_high = 0
    sum_medium = 0
    sum_low = 0
    server_high = 0
    server_medium = 0
    server_low = 0
    table_data = [['Hostname', 'IP', 'Informe', 'high', 'medium', 'low']]
    #table_data = [['IP', 'Informe', 'high', 'medium', 'low']]

    for asset in assets_xml.xpath('asset'):
        ip = asset.xpath('name/text()')[0]
        #print(ip)

        hostnames = asset.xpath(
            'identifiers/identifier/name[text()="hostname"]/../value/text()'
       )

        #print (hostnames)
        if len(hostnames)>0:
            hostname = hostnames[0]
            #print (hostname)
        else:
            hostname = "no disponible"
            #print (hostname)

        results = gmp.get_results(
            details=False, filter='host={0} and severity>0.0'.format(ip)
        )

        low = int(results.xpath('count(//result/threat[text()="Low"])'))
        sum_low += low

        medium = int(results.xpath('count(//result/threat[text()="Medium"])'))
        sum_medium += medium
        if medium >0: server_medium += 1

        high = int(results.xpath('count(//result/threat[text()="High"])'))
        sum_high += high
        if high >0: server_high += 1

        best_os_cpe_report_id = asset.xpath('host/detail/name[text()="best_os_cpe"]/../source/@id')
        if len(best_os_cpe_report_id)>0:
            best_os_cpe_report_id = best_os_cpe_report_id[0]
        else:
            best_os_cpe_report_id = "no disponible"

        hostname=hostname.split('.',1)[0]
        table_data.append(
            [hostname,ip, best_os_cpe_report_id, high, medium, low]
        )

    table = AsciiTable(table_data)
    nservidores=len(assets_xml)
    print('\\begin{verbatim}')   
    print( 'Numero total de servidores escaneados en el periodo = {5}'
        '\nBusqueda de resultados desde {3} 00:00 a {4} 00:00 '
        '\n\nVulnerabilidades Nivel:'
        '\n - High:   {0}'
        '\n - Medium: {1}'
        '\n - Low:    {2}\n'.format(
            int(sum_high),
            int(sum_medium),
            int(sum_low),
            from_date.isoformat(),
            to_date.isoformat(),
            int(nservidores)
        )
    )
    print(
        '\nNumero de Servidores con vulnerabilidad:'
        '\n - High:   {0} = {1}% del total de servidores analizados'
        '\n - Medium: {2}\n'.format(
            int(server_high),
            int(server_high*100/nservidores),
            int(server_medium)
        )
    )
    print('\end{verbatim}')   
    print('\section{Vulnerabilidades por Host}')   
    print('\\begin{verbatim}')   
    print(table.table + '\n')
    print('\end{verbatim}')   

def print_report_vulns(gmp, from_date, to_date):
    vulns_filter = "severity>7 and newest>{0} sort-reverse=severity rows=-1".format(from_date.isoformat())
    vulns_xml = gmp.get_vulnerabilities(filter=vulns_filter)
    #pretty_print(vulns_xml)
    table_data_OS_vuln = [['Severity', 'name']]
    table_data_vuln = [['Severity', 'name']]
    for vulnerability in vulns_xml.xpath('vuln'):
        name = vulnerability.xpath('name/text()')[0]
        severity = vulnerability.xpath('severity/text()')[0]
        if 'End Of Life' in name:
           table_data_OS_vuln.append([severity,name])
        else:
           table_data_vuln.append([severity,name])

    print('\section{Top Vulnerabilidades }')   
    print('Lista de vulnerabilidades del mes, filtro utilizado:')
    print('\\begin{verbatim} '+vulns_filter+' \end{verbatim}')
    print('\subsection {Lista de vulneralidades End of Life}')
    print('\\begin{itemize}')
    for item in table_data_OS_vuln: print ('\\item \\begin{verbatim}'+ item[0] +', ' +item[1]+' \\end{verbatim}')
    print('\\end{itemize}')

    print('\subsection {Lista de vulneralidades presentes de categoria High}')
    print('\\begin{itemize}')
    for item in table_data_vuln: print ('\\item \\begin{verbatim}'+ item[0] +', ' +item[1]+' \\end{verbatim}')
    print('\\end{itemize}')


def main(gmp, args):
    # pylint: disable=undefined-variable

    check_args(args)

    month = int(args.script[1])
    year = int(args.script[2])
    from_date = date(year, month, 1)
    to_date = from_date + timedelta(days=31)
    # To have the first day in month
    to_date = to_date.replace(day=1)

    print_reports(gmp, from_date, to_date)
    print_report_vulns(gmp, from_date, to_date)


if __name__ == '__gmp__':
    main(gmp, args)
