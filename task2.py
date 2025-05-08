#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Завдання 2. Порівняння продуктивності HyperLogLog із точним підрахунком унікальних елементів
"""

import re
import time
import mmh3
import math
from tabulate import tabulate


class HyperLogLog:
    """
    Реалізація алгоритму HyperLogLog для наближеного підрахунку унікальних елементів
    з використанням мінімальної кількості пам'яті.
    """
    def __init__(self, p=14):
        """
        Ініціалізація HyperLogLog.
        
        Args:
            p (int): Параметр точності, визначає кількість регістрів як 2^p.
                     За замовчуванням 14, що дає 16384 регістрів.
        """
        self.p = p
        self.m = 1 << p  # кількість регістрів (2^p)
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        
    def _get_alpha(self):
        """
        Визначає константу alpha для корекції систематичної похибки.
        
        Returns:
            float: Значення константи alpha.
        """
        if self.p == 4:
            return 0.673
        elif self.p == 5:
            return 0.697
        elif self.p == 6:
            return 0.709
        else:
            return 0.7213 / (1 + 1.079 / self.m)
            
    def _rho(self, w):
        """
        Обчислює кількість провідних нулів плюс 1 у бінарному представленні числа.
        
        Args:
            w (int): Число для аналізу.
            
        Returns:
            int: Кількість провідних нулів + 1.
        """
        return len(bin(w | (1 << 32))) - len(bin(w)) if w > 0 else 33
        
    def add(self, item):
        """
        Додає елемент до HyperLogLog.
        
        Args:
            item (str): Елемент для додавання.
        """
        # Обчислюємо хеш елемента
        x = mmh3.hash(str(item), signed=False)
        
        # Використовуємо p нижніх бітів як індекс регістра
        j = x & (self.m - 1)
        
        # Використовуємо решту бітів для визначення кількості провідних нулів
        w = x >> self.p
        
        # Оновлюємо регістр максимальним значенням кількості провідних нулів
        self.registers[j] = max(self.registers[j], self._rho(w))
        
    def count(self):
        """
        Оцінює кількість унікальних елементів.
        
        Returns:
            float: Оцінка кількості унікальних елементів.
        """
        # Обчислюємо обернене середнє гармонійне
        Z = sum(2.0 ** -r for r in self.registers)
        Z = 1.0 / Z
        
        # Застосовуємо корекційну формулу
        E = self.alpha * self.m * self.m * Z
        
        # Корекція для малих значень
        if E <= 2.5 * self.m:
            # Обчислюємо кількість пустих регістрів
            V = self.registers.count(0)
            if V > 0:
                # Використовуємо лінійний підрахунок для малих значень
                return self.m * math.log(self.m / V)
        
        # Корекція для великих значень
        if E > (1.0 / 30.0) * (1 << 32):
            E = -pow(2, 32) * math.log(1 - E / pow(2, 32))
            
        return E


def load_ip_addresses(file_path):
    """
    Завантажує IP-адреси з лог-файлу.
    
    Args:
        file_path (str): Шлях до лог-файлу.
        
    Returns:
        list: Список IP-адрес.
    """
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_addresses = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                # Шукаємо IP-адреси в рядку
                matches = re.findall(ip_pattern, line)
                if matches:
                    # Перевіряємо, що кожен октет в IP-адресі коректний (0-255)
                    for ip in matches:
                        if is_valid_ip(ip):
                            ip_addresses.append(ip)
    except FileNotFoundError:
        print(f"Помилка: Файл '{file_path}' не знайдено.")
    except Exception as e:
        print(f"Помилка при обробці файлу: {str(e)}")
        
    return ip_addresses


def is_valid_ip(ip):
    """
    Перевіряє, чи є IP-адреса коректною (кожен октет в діапазоні 0-255).
    
    Args:
        ip (str): IP-адреса для перевірки.
        
    Returns:
        bool: True, якщо IP-адреса коректна, інакше False.
    """
    octets = ip.split('.')
    if len(octets) != 4:
        return False
        
    for octet in octets:
        try:
            num = int(octet)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
            
    return True


def exact_count_unique(items):
    """
    Точний підрахунок унікальних елементів за допомогою структури set.
    
    Args:
        items (list): Список елементів.
        
    Returns:
        int: Кількість унікальних елементів.
    """
    return len(set(items))


def approx_count_unique(items):
    """
    Наближений підрахунок унікальних елементів за допомогою HyperLogLog.
    
    Args:
        items (list): Список елементів.
        
    Returns:
        float: Оцінка кількості унікальних елементів.
    """
    hll = HyperLogLog(p=14)  # p=14 забезпечує похибку ~0.81%
    for item in items:
        hll.add(item)
    return hll.count()


def compare_methods(items):
    """
    Порівнює точний підрахунок та HyperLogLog за часом виконання та результатом.
    
    Args:
        items (list): Список елементів для аналізу.
        
    Returns:
        dict: Результати порівняння.
    """
    # Точний підрахунок
    start_time = time.time()
    exact_count = exact_count_unique(items)
    exact_time = time.time() - start_time
    
    # Наближений підрахунок (HyperLogLog)
    start_time = time.time()
    approx_count = approx_count_unique(items)
    approx_time = time.time() - start_time
    
    # Обчислення похибки
    error = abs(exact_count - approx_count) / exact_count * 100 if exact_count > 0 else 0
    
    return {
        "exact_count": exact_count,
        "approx_count": approx_count,
        "exact_time": exact_time,
        "approx_time": approx_time,
        "error": error
    }


def main():
    """
    Головна функція програми.
    """
    # Шлях до лог-файлу
    log_file = "lms-stage-access.log"
    
    print("Завантаження IP-адрес з лог-файлу...")
    ip_addresses = load_ip_addresses(log_file)
    
    if not ip_addresses:
        print("Не вдалося завантажити IP-адреси. Перевірте наявність файлу та його формат.")
        return
        
    print(f"Завантажено {len(ip_addresses)} IP-адрес.")
    
    # Порівняння методів
    print("\nПорівняння методів підрахунку унікальних IP-адрес...")
    results = compare_methods(ip_addresses)
    
    # Виведення результатів у вигляді таблиці
    table_data = [
        ["Унікальні елементи", results["exact_count"], results["approx_count"]],
        ["Час виконання (сек.)", results["exact_time"], results["approx_time"]]
    ]
    
    table_headers = ["", "Точний підрахунок", "HyperLogLog"]
    table = tabulate(table_data, headers=table_headers, tablefmt="grid")
    
    print("\nРезультати порівняння:")
    print(table)
    print(f"\nВідносна похибка HyperLogLog: {results['error']:.2f}%")


if __name__ == "__main__":
    main()