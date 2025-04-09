package envoy.authz

default allow = false

allow if {
  input.attributes.request.http.method == "GET"
  input.parsed_path == ["api", "data", "references", "medcards", "items", ""]

  # Получаем токен из заголовка Authorization
  token := get_token_from_header(input.attributes.request.http.headers["authorization"])

  # Распарсим без проверки подписи
  # TODO: реализуйте проверку подписи самостоятельно
  # с помощью, например, io.jwt.verify_rs256
  [_, payload, _] := io.jwt.decode(token)

  # Достаём query-параметр и claim
  region_param := input.parsed_query["medcard-region"]
  region_claim := payload["region"]

  # Сравниваем
  region_param == region_claim
}

# Функция извлекает токен из "Authorization: Bearer <token>"
get_token_from_header(header) = token if {
  startswith(header, "Bearer ")
  parts := split(header, " ")
  count(parts) == 2
  token := parts[1]
}
