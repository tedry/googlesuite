# -*- coding: utf-8 -*-

import sys

import unicodecsv as csv
from datetime import datetime

from overrides import overrides

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from o_common import json_dump, Command, human_sorted


class Connector(Command):
    ''' Base class for all connectors '''

    @classmethod
    def get_metrics(self):
        '''Returns a list of metric names which this connector supports.
           The connector should provide collect_<metric> and optionally
           analyze_<metric> methods for each metric defined here'''
        return []

    @classmethod
    def get_persist_options(self, metric):
        ''' Returns a dict with options for db_load '''
        return {}

    @overrides
    def run(self):
        self.log.info('Start')

        self.start_up()
        self.log.info('Completed start up')

        for metric in self.get_metrics():

            collected = self.collect(metric)
            self.log.info('Completed collecting %s', metric)

            if not collected: continue

            self.write_collected(metric, collected)
            self.log.info('Wrote collected data for %s', metric)

            analyzed = self.analyze(metric, collected)
            self.log.info('Completed analysing %s', metric)

            if not analyzed: continue

            self.write_analyzed(metric, analyzed)
            self.log.info('Wrote analyzed data for %s', metric)

        self.shut_down()
        self.log.info('Finished')

        return 0

    def start_up(self):
        'Performs any setup required for this session'
        pass

    def collect(self, metric):
        ''' Connects to device and collects data for supplied metric '''
        return getattr(self, 'collect_' + metric)()  # will throw if method not defined

    def write_collected(self, metric, collected):
        ''' Writes collected data to JSON files (one per metric)'''

        output = metric + '.json'
        with open(output, 'wb') as f:
            f.write(json_dump(collected))

    def analyze(self, metric, collected):
        ''' Analyzes collected data '''
        analyzer = getattr(self, 'analyze_' + metric, None)
        if analyzer:
            return analyzer(collected)
        return collected

    def write_analyzed(self, metric, analyzed):
        ''' Writes analyzed data to CSV file '''

        if not analyzed:
            return

        output = metric + '.out'
        self.log.info('start writing output file: %s ...', output)
        with open(output, 'wb') as f:

            columns = analyzed[0].keys()
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()

            for measurement in analyzed:
                for k, v in measurement.items():
                    if k == 'value_json':
                        measurement[k] = json_dump(v, multi_line=False) if v else ''
                    elif isinstance(v, datetime):
                        measurement[k] = v.isoformat()
                    elif isinstance(v, (set)):
                        measurement[k] = ','.join(human_sorted(v))
                    elif isinstance(v, (list, tuple)):
                        measurement[k] = ','.join(v)
                writer.writerow(measurement)
        self.log.info('finish writing output file: %s', output)

    def shut_down(self):
        'Performs cleanup'
        pass


class ConnectorCommand(Command):
    @classmethod
    def get_name(cls):
        return 'connector'

    @classmethod
    def create_arg_parser(cls):
        from . import registry

        parser = ArgumentParser(description=cls.get_description(), formatter_class=ArgumentDefaultsHelpFormatter,
                                add_help=False)
        cls.add_global_args(parser)

        # For each connector in the registry, add as subcommand
        subparsers = parser.add_subparsers(help='Choose name', dest='connector_name')
        for connector_name, connector_class in registry.items():
            sub_parser = subparsers.add_parser(connector_name, help=connector_class.get_description())
            connector_class.add_custom_args(sub_parser)
        return parser

    def run(self):
        from . import registry
        connector_class = registry.get(self.options.connector_name)
        if connector_class:
            connector = connector_class(self.options)
            connector.run()


if __name__ == '__main__':
    sys.exit(ConnectorCommand.main())