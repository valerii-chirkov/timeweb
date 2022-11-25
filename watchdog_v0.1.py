#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""watchdog_v0.1.py: ..."""
import datetime
import sqlite3 as sl
import os
import argparse
import sys
import time
import hashlib
import logging
import traceback


def create_tables(con=None) -> None:
    with con:
        try:
            con.execute("""
                create table directories (
                    id integer primary key autoincrement,
                    parent_id integer null,
                    dirname varchar(50)
                );
            """)
        except Exception as e:
            logging.info(e)
        try:
            con.execute("""
                create table files (
                    id integer primary key autoincrement,
                    dir_id integer,
                    filename varchar(255),
                    modtime datetime,
                    file_permissions integer(3),
                    file_hash varchar(255)
                );
            """)
        except Exception as e:
            logging.info(e)


class argparse_logger(argparse.ArgumentParser):
    def _print_message(self, message: str, file: str = None) -> None:
        if file is sys.stderr:
            logger.error(message)
        else:
            super()._print_message(message, file=file)


def log_uncaught_exceptions(ex_cls, ex, tb):
    logging.critical(''.join(traceback.format_tb(tb)))
    logging.critical('{0}: {1}'.format(ex_cls, ex))


log_path = f"./log_{time.time()}.log"
logger = logging.getLogger('root')
sys.excepthook = log_uncaught_exceptions


def insert_dir(table: str, parent_id: str, dirname: str) -> None:
    with con:
        try:
            sql_query = "insert into {} (parent_id, dirname) values {}".format(table, (parent_id, dirname))
            con.execute(sql_query)
        except Exception as e:
            print(e)


def get_last_id(table: str) -> str | None:
    with con:
        try:
            sql_query = "select max(id) from {}".format(table)
            res = con.execute(sql_query).fetchmany(size=1)
            return res[0][0]
        except Exception as e:
            print(e)


def get_root_id(table: str, dirname: str) -> str | None:
    with con:
        try:
            sql_query = "select id from {} where dirname='{}' order by id desc".format(table, dirname)
            res = con.execute(sql_query).fetchmany(size=1)
            return res[0][0]
        except Exception as e:
            print(e)


def get_sha256_hash(filename: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


def insert_file(table: str, dir_id: str, filename: str, m_time: str, file_permissions: str, file_hash: str) -> None:
    with con:
        try:
            sql_query = """
                insert into {} (
                    dir_id, filename, modtime, file_permissions, file_hash
                ) values {}
            """.format(table, (dir_id, filename, m_time, file_permissions, file_hash))
            con.execute(sql_query)
        except Exception as e:
            print(e)


def recursive_walk(folder: str) -> None:
    for root, dirs, files in os.walk(folder):
        if root == '.':
            parent_id = 'NULL'
        elif dirs:
            parent_id = get_root_id(table='directories', dirname=root.split('/')[-1])
        else:
            parent_id = get_last_id(table='directories')

        for filename in files:
            file_path = os.path.join(root, filename)
            m_time = os.path.getmtime(file_path)
            m_time_hr = datetime.datetime.fromtimestamp(m_time)
            insert_file(table='files', dir_id=parent_id, filename=filename,
                        m_time=str(m_time_hr),
                        file_permissions=oct(os.stat(file_path).st_mode)[-3:],
                        file_hash=get_sha256_hash(file_path)
                        )

            logging.info('file_path: {}'.format(file_path))

        for dirname in dirs:
            dir_path = os.path.join(root, dirname)
            insert_dir(table='directories', parent_id=parent_id, dirname=dirname)

            logging.info('dir_path: {}'.format(dir_path))


if __name__ == "__main__":
    parser = argparse_logger()
    # parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory",
                        help="полный или относительный путь к директории, из которой наполняется база "
                             "(обязательный аргумент)",
                        default='.')
    parser.add_argument("-b", "--database",
                        help="полный или относительный путь к базе данных, "
                             "в которой будут сохраняться данные по директории "
                             "(обязательный аргумент)",
                        default='/timeweb.db')
    parser.add_argument("-v", "--verbose", required=False,
                        help="флаг, показывающий, что необходимо выводить информацию на консоль. "
                             "По умолчанию скрипт не должен ничего выводить в терминал кроме информации "
                             "по использованию при недостаточных аргументах "
                             "или аргументе -h/--help "
                             "(необязательный аргумент)")
    parser.add_argument("-l", "--log",
                        help="полный или относительный путь к файлу лога. "
                             "Если в логе уже есть записи, они должны остаться. "
                             "(обязательный аргумент)",
                        default=log_path)

    args = parser.parse_args()
    logging.basicConfig(filename=args.log, filemode='a', format='[%(asctime)s] %(levelname)s %(message)s',
                        level=logging.INFO)

    logging.info('Start of the script')
    logging.info('Args: {}'.format(vars(args)))

    logging.error(vars(args))

    con = sl.connect(args.database)
    create_tables(con)
    recursive_walk(args.directory)

    logging.info('End of the script')
