"""
Модуль для перевірки унікальності паролів за допомогою фільтра Блума.

Фільтр Блума - імовірнісна структура даних, яка дозволяє ефективно перевіряти 
належність елемента до множини без зберігання самих елементів.
"""

import hashlib


class BloomFilter:
    """
    Реалізація фільтра Блума для ефективної перевірки наявності елемента в множині.

    Параметри:
        size (int): Розмір бітового масиву.
        num_hashes (int): Кількість хеш-функцій.
    """

    def __init__(self, size, num_hashes):
        """
        Ініціалізація фільтра Блума із вказаним розміром та кількістю хеш-функцій.

        Args:
            size (int): Розмір бітового масиву.
            num_hashes (int): Кількість хеш-функцій.
        """
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = [0] * size

    def _get_hash_indexes(self, item):
        """
        Отримує індекси хеш-функцій для елемента.

        Args:
            item: Елемент для хешування.

        Returns:
            list: Список індексів у бітовому масиві.
        """
        if not isinstance(item, str):
            item = str(item)

        indexes = []
        # Використовуємо різні алгоритми хешування для генерації різних хеш-значень
        hash_algorithms = [
            hashlib.md5,
            hashlib.sha1,
            hashlib.sha256,
            hashlib.sha512,
            hashlib.sha3_256
        ]

        # Беремо мінімум між кількістю потрібних хеш-функцій та доступними алгоритмами
        alg_count = min(self.num_hashes, len(hash_algorithms))

        for i in range(alg_count):
            # Використовуємо i-й алгоритм хешування
            hash_obj = hash_algorithms[i % len(hash_algorithms)]()
            # Додаємо сіль, засновану на індексі, щоб отримати різні хеш-значення
            # навіть при використанні одного й того ж алгоритму
            hash_obj.update((item + str(i)).encode('utf-8'))
            # Отримуємо хеш-значення у вигляді числа
            hash_value = int.from_bytes(hash_obj.digest(), byteorder='big')
            # Беремо індекс за модулем розміру бітового масиву
            index = hash_value % self.size
            indexes.append(index)

        # Для решти хеш-функцій генеруємо похідні значення
        if alg_count < self.num_hashes:
            for i in range(alg_count, self.num_hashes):
                # Використовуємо комбінацію вже отриманих індексів
                combined = sum(indexes) + i * 31
                indexes.append(combined % self.size)

        return indexes

    def add(self, item):
        """
        Додає елемент до фільтра.

        Args:
            item: Елемент для додавання.
        """
        for index in self._get_hash_indexes(item):
            self.bit_array[index] = 1

    def contains(self, item):
        """
        Перевіряє, чи може елемент бути у фільтрі.

        Args:
            item: Елемент для перевірки.

        Returns:
            bool: True, якщо елемент може бути у фільтрі, False інакше.
        """
        for index in self._get_hash_indexes(item):
            if self.bit_array[index] == 0:
                return False
        return True


def check_password_uniqueness(bloom_filter, passwords):
    """
    Перевіряє унікальність паролів за допомогою фільтра Блума.

    Args:
        bloom_filter (BloomFilter): Ініціалізований фільтр Блума.
        passwords (list): Список паролів для перевірки.

    Returns:
        dict: Словник результатів перевірки для кожного пароля.
    """
    results = {}

    for password in passwords:
        if not password:  # Перевірка на порожній пароль
            results[password] = "неприпустимий (порожній пароль)"
            continue

        if bloom_filter.contains(password):
            results[password] = "вже використаний"
        else:
            results[password] = "унікальний"
            # Додаємо пароль до фільтра після перевірки
            bloom_filter.add(password)

    return results


if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' - {status}.")
