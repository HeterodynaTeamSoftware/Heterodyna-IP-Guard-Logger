=== IP Guard Logger (Śledzenie IP i incydentów) ===
Wersja: 01.001.0003
Autor: Heterodyna Team Software
Strona: https://heterodynateamsoftware.pl

== Co zmieniono w 01.001.0003 ==

- Przebudowano tabelę logów pod widok 100% w przeglądarce.
- Zmniejszono liczbę kolumn z 8 do 6.
- Metoda HTTP, status i ścieżka są teraz w jednej kompaktowej kolumnie „Żądanie”.
- Długie ścieżki są skracane w tabeli, a pełna wartość pozostaje dostępna po najechaniu.
- JSON w szczegółach zawija długie linie i nie rozszerza tabeli.
- Dodano stałe szerokości kolumn i table-layout: fixed.
- Zagęszczono odstępy, czcionki i nagłówki tabel.
- Przegląd IP również korzysta z kompaktowego układu.

== Co zmieniono w 01.001.0002 ==

- Logi nie są już zapisywane w osobnych katalogach per IP.
- Nowe logi trafiają do tabel bazy danych WordPressa.
- Pełny podgląd logów jest dostępny bezpośrednio w panelu wtyczki.
- Dodano stronicowanie po 50 IP i 100 zdarzeń, dzięki czemu panel nie skanuje tysięcy folderów przy każdym wejściu.
- Dodano filtrowanie logów po IP i typie zdarzenia.
- Dodano jednorazowy import starych logów z wp-content/uploads/ip-guard-logs/.
- Import działa partiami przez AJAX, żeby nie blokować panelu.
- Zewnętrzne sprawdzanie IP (ip-api / AbuseIPDB) działa asynchronicznie przez WP-Cron.
- Wrażliwe nagłówki i cookies są maskowane w logach.
- Dodano opcjonalną retencję zdarzeń.

== Dlaczego poprzednia wersja była wolna ==

Poprzednia wersja przy każdym wejściu do panelu otwierała katalog logów, przechodziła po wszystkich folderach IP,
czytała każdy plik ip-meta.json i dopiero wtedy sortowała wyniki.

Przy kilku tysiącach IP oznaczało to tysiące operacji dyskowych na jedno otwarcie strony administratora.

Wersja 01.001.0002 korzysta z indeksowanych tabel bazy danych i pobiera tylko rekordy potrzebne do aktualnej strony.

== Migracja ==

Po aktualizacji wejdź w:

IP Guard Logger -> Przegląd

Jeżeli wtyczka wykryje stare logi plikowe, pojawi się przycisk:

"Importuj stare logi do bazy"

Stare katalogi nie są automatycznie kasowane. Po udanym imporcie mogą pozostać jako kopia bezpieczeństwa.

== RODO/GDPR ==

Wtyczka zapisuje adresy IP i informacje o zachowaniu użytkowników. Ustal podstawę prawną, okres retencji
oraz odpowiednio opisz przetwarzanie danych w polityce prywatności.
