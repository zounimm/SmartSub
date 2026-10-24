# -*- coding: utf-8 -*-

import sys

import os

import datetime

import yaml

from loguru import logger

sub_path = 'sub' #默认存放订阅源的文件夹名称

sub_all_yaml = os.path.join(sub_path, 'sub_all.yaml')

config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.yaml')

DEFAULT_KEEP_RECENT = 7

today = datetime.datetime.today()

path_year = os.path.join(sub_path, str(today.year))

path_mon = os.path.join(path_year, str(today.month))

path_yaml = os.path.join(path_mon, f'{today.month}-{today.day}.yaml')

def _keep_recent():

    """读取 retention.keep_recent，失败时用默认值。"""

    try:

        with open(config_path, encoding='utf-8') as f:

            data = yaml.safe_load(f) or {}

        return max(0, int((data.get('retention') or {}).get('keep_recent', DEFAULT_KEEP_RECENT)))

    except Exception as e:

        logger.warning(f'读取 retention.keep_recent 失败，使用默认 {DEFAULT_KEEP_RECENT}: {e}')

        return DEFAULT_KEEP_RECENT

def _iter_archives():

    """遍历 sub/YYYY/MM/*.yaml，返回 [(date, 目录, 文件名)]。"""

    entries = []

    if not os.path.isdir(sub_path):

        return entries

    for year_dir in os.listdir(sub_path):

        year_path = os.path.join(sub_path, year_dir)

        if not (year_dir.isdigit() and os.path.isdir(year_path)):

            continue

        for mon_dir in os.listdir(year_path):

            mon_path = os.path.join(year_path, mon_dir)

            if not (mon_dir.isdigit() and os.path.isdir(mon_path)):

                continue

            for name in os.listdir(mon_path):

                if not name.endswith('.yaml'):

                    continue

                parts = name[:-5].split('-')

                if len(parts) != 2:

                    continue

                try:

                    file_date = datetime.date(int(year_dir), int(mon_dir), int(parts[1]))

                except ValueError:

                    continue

                entries.append((file_date, mon_path, name))

    return entries

def cleanup_old_archives(keep_recent=None):

    """只保留最新的 N 个归档文件，其余删除，并清理空目录。"""

    keep = _keep_recent() if keep_recent is None else keep_recent

    if keep <= 0:

        return

    entries = _iter_archives()

    if len(entries) <= keep:

        return

    entries.sort(key=lambda item: item[0], reverse=True)

    removed = 0

    for _, mon_path, name in entries[keep:]:

        try:

            os.remove(os.path.join(mon_path, name))

            removed += 1

        except OSError as e:

            logger.warning(f'删除归档失败 {name}: {e}')

    # 清理被删空的月/年目录

    for year_dir in os.listdir(sub_path):

        year_path = os.path.join(sub_path, year_dir)

        if not (year_dir.isdigit() and os.path.isdir(year_path)):

            continue

        for mon_dir in os.listdir(year_path):

            mon_path = os.path.join(year_path, mon_dir)

            if not (mon_dir.isdigit() and os.path.isdir(mon_path)):

                continue

            try:

                if not os.listdir(mon_path):

                    os.rmdir(mon_path)

            except OSError:

                pass

        try:

            if not os.listdir(year_path):

                os.rmdir(year_path)

        except OSError:

            pass

    if removed:

        logger.info(f'🧹 已清理 {removed} 个归档，保留最近 {keep} 个')

@logger.catch

def pre_check():

    os.makedirs(path_mon, exist_ok=True)

    cleanup_old_archives()

    logger.info('初始化完成')

    return path_yaml

@logger.catch

def get_sub_all():

    return sub_all_yaml

# pre_check()
