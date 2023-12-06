# Алгоритм Ель-Гамаля. Цифровий підпис. Спрямоване шифрування
## Завдання
### Власна реалізація цифрового підпису
Напишіть власну програмну реалізацію цифрового підпису за алгоритмом Ель-Гамаля. Зверніть увагу на порядок вибору загальносистемних параметрів та генерацію ключів відповідно до них. Наведемо кроки алгоритму для кожного з епатів.

Вибір загальносистемних параметрів:
+ Згенеруйте випадкове просте число p довжиною від 2048 до 4096 бітів, яке служить модулем для арифметичних операцій у скінченному полі.
+ Виберіть випадкове число g, яке є примітивним коренем модуля p, і воно має генерувати всі елементи поля від 1 до p-1.

Генерація ключів:
+ Оберіть випадкове число a (особистий ключ), що належить інтервалу (1, p-1).
+ Обчисліть відкритий ключ b = g^a mod p.

Підписання повідомлення:
+ Оберіть випадкове число k, яке належить інтервалу (1, p-1).
+ Обчисліть перший компонент підпису: r = g^k mod p.
+ Обчисліть другий компонент підпису: s = (H(m) - a*r) * k^(-1) mod (p-1), де H(m) – геш-значення від повідомлення m.
+ Підписом повідомлення буде пара значень (r, s).

Перевірка підпису:
+ Обчисліть обернений елемент до відкритого ключа: y = b^(-1) mod p.
+ Обчисліть першу складову перевірки: u1 = (H(m) * s^(-1)) mod (p-1).
+ Обчисліть другу складову перевірки: u2 = (r * s^(-1)) mod (p-1).
+ Обчисліть перевірочне значення: v = (g^u1 * y^u2) mod p.
+ Підпис вважається вірним, якщо v = r.

### Власна реалізація спрямованого шифрування
Напишіть власну програмну реалізацію спрямованого шифрування за алгоритмом Ель-Гамаля. Зверніть увагу на розбиття повідомлення на блоки і шифрування кожного блока окремо. Якщо ви вже реалізували відповідний алгоритм цифрового підпису, з шифруванням вам буде значно простіше. Наведемо кроки алгоритму для кожного з епатів.

Вибір загальносистемних параметрів:
+ Згенеруйте випадкове просте число p з довжиною від 2048 до 4096 бітів, яке служить модулем для арифметичних операцій у скінченному полі.
+ Виберіть випадкове число g, яке є примітивним коренем модуля p, і воно має генерувати всі елементи від 1 до p-1.

Генерація ключів:
+ Оберіть випадкове число a (особистий ключ), що належить інтервалу (1, p-1).
+ Обчисліть відкритий ключ b = g^a mod p.

Зашифрування повідомлення:
+ Відправник обирає повідомлення m, яке потрібно зашифрувати, і випадкове число k, яке необхідне для шифрування
+ x = g^k mod p
+ y = (b^k * m) mod p
+ де m – числове представлення повідомлення
+ Відправник відправляє шифротекст (x, y) одержувачу

Розшифрування повідомлення:
+ Отримавши шифротекст (x, y), одержувач може розшифрувати повідомлення за допомогою свого особистого ключа a
+ s = x^a mod p
+ m = (y * (s^(-1))) mod p, де s^(-1) – обернене до s в полі за модулем p
+ m – розшифроване повідомлення

### Перевірка коректності реалізації
Метою цього етапу є виклик функцій підпису і перевірки зі згенерованими вами ключами для певного тестового повідомлення. І переконання в тому, що цифровий підпис правильний. А також перевірка цього сценарію з пошкодженними даними і впевненість, що алгоритм перевірки підпису повертає «false».
Для спрямованого шифрування достатньо перевірити, що зашифроване вашою функцією повідомлення правильно розшифровується. З урахуванням того, що від початку повідомлення може бути значно більше аніж модуль p і його треба розбивати на блоки.

## Інструкція щодо запуска коду
Код розроблено з використанням Python 3.10.7. Для запуску коду необхідно мати встановлений Python відповідної або більш нової версії та прописати наступну консольну команду у директорії файлу:
```python
python .\Elgamal_Kitsun.py
```
## Приклад визову програми та результату виконання програми
Приклад визову програми та результату виконання програми зображено на рисунку нижче. Також даний скріншот можна знайти в репозиторії.

![Code_exectuion_example](https://github.com/KKitsun/MyElgamal/blob/master/Elgamal_ExecutionTest.PNG)

