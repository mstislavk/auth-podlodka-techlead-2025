Каждая директория в корне является набором разных сервисов выполняющих идентичные функции

### envoy-opa

* PEP — Envoy
* PDP — Open Policy Agent

### nginx-python-pdp

* PEP — nginx
* PDP — Python сервис 

### nginx-jsonschema-pdp

* PEP — nginx
* PDP — Python-сервис с политиками на JSON Schema

### Поднять сервисы

Выберите один из трёх вариантов, перейдите в директорию с ним и выполните 

```
docker compose up --build
```


### Неавторизованный запрос

```
curl "http://localhost/api/data/references/medcards/items/?medcard-region=7" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ItCU0L7QutGC0L7RgCDQkNC50LHQvtC70LjRgiIsImdyb3VwIjoiZG9jdG9yIiwicmVnaW9uIjpbIjgiXSwiaWF0IjoxNTE2MjM5MDIyfQ.h1lJIcK59_5LeT6taI_c6bV1zOd3XEAiZFC12nlqDWaZOfn0s9GtDZH_4lrhCQ07sQPa2sQLLAMS-ZWZmwQh01dSpVs-8Sq_dLLFPdEJODpUmozLP02Xx59E2RdmHYTyXWGtdysfXmFCqUUKXoZ3rIkN_wdwgolp3YZSs3vDw5eyJKhiADeT-Jfrvrso6wioiHcsT9C-VncFBWQXZDi7Ehs_wf2xzwYCRCZOgIQLwuBh1urzi0eMzE-gXYnxiDrLsLr8yTHjidiSGWEcjbDkulHDiJi7_BwecgwL-bPpx2Bv4yV1bVM76ua8R-cCwnEnOg-_UZemHPsHl2A3nDp71vx3TLS_3i_Qeaan-dpaxkp5HUGyfG-OVPjbw4PTewL9vam8KK0eiu4YTkOI32ssX8_dBBCAVR7cg8-Mt97nJyA1J2wis9KWf7FLpqVUm-HhP0pme4vAvn-APttZjOq586czwf43dv4GGHT1HsnUIYcfoUAXiXbsD7pt0cqiy5Y8XSFFvHD4P6L94i17hWpTb4Voi92lGCtj64pbG3OsKgCcsHAXSySJxkg5aWJq5xKsxyLK1pToxkEUyOOhBq3Y5Yaf0anbgBMqtCx9t-e9AyKdM31p7KGBsEpKoBsj40MS9hZKkRYV9nPYxMcC5pB49egypI2SIMb-03gWUtjok6s"
```

### Авторизованный запрос

```
curl "http://localhost/api/data/references/medcards/items/?medcard-region=8" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ItCU0L7QutGC0L7RgCDQkNC50LHQvtC70LjRgiIsImdyb3VwIjoiZG9jdG9yIiwicmVnaW9uIjpbIjgiXSwiaWF0IjoxNTE2MjM5MDIyfQ.h1lJIcK59_5LeT6taI_c6bV1zOd3XEAiZFC12nlqDWaZOfn0s9GtDZH_4lrhCQ07sQPa2sQLLAMS-ZWZmwQh01dSpVs-8Sq_dLLFPdEJODpUmozLP02Xx59E2RdmHYTyXWGtdysfXmFCqUUKXoZ3rIkN_wdwgolp3YZSs3vDw5eyJKhiADeT-Jfrvrso6wioiHcsT9C-VncFBWQXZDi7Ehs_wf2xzwYCRCZOgIQLwuBh1urzi0eMzE-gXYnxiDrLsLr8yTHjidiSGWEcjbDkulHDiJi7_BwecgwL-bPpx2Bv4yV1bVM76ua8R-cCwnEnOg-_UZemHPsHl2A3nDp71vx3TLS_3i_Qeaan-dpaxkp5HUGyfG-OVPjbw4PTewL9vam8KK0eiu4YTkOI32ssX8_dBBCAVR7cg8-Mt97nJyA1J2wis9KWf7FLpqVUm-HhP0pme4vAvn-APttZjOq586czwf43dv4GGHT1HsnUIYcfoUAXiXbsD7pt0cqiy5Y8XSFFvHD4P6L94i17hWpTb4Voi92lGCtj64pbG3OsKgCcsHAXSySJxkg5aWJq5xKsxyLK1pToxkEUyOOhBq3Y5Yaf0anbgBMqtCx9t-e9AyKdM31p7KGBsEpKoBsj40MS9hZKkRYV9nPYxMcC5pB49egypI2SIMb-03gWUtjok6s"
```
