# Changelog

## 01.001.0003

- Przebudowany, kompaktowy widok logów dopasowany do przeglądarki przy 100% powiększenia.
- Logi i podsumowania IP przechowywane w bazie WordPressa zamiast w osobnych folderach per IP.
- Stronicowanie listy IP i zdarzeń.
- Filtrowanie logów po IP i typie zdarzenia.
- Jednorazowa migracja starych logów plikowych do bazy danych.
- Asynchroniczne wzbogacanie IP przez WP-Cron.
- Integracja z ip-api i opcjonalnie AbuseIPDB.
- Maskowanie wybranych wrażliwych nagłówków i cookies.
- Opcjonalny soft-block HTTP 429 na podstawie wyniku podejrzaności.
- Konfigurowalna retencja logów.
