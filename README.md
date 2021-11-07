# Проектная работа 7 спринта

Упростите регистрацию и аутентификацию пользователей в Auth-сервисе, добавив вход через социальные сервисы. 
Список сервисов выбирайте исходя из целевой аудитории онлайн-кинотеатра — подумайте, какими социальными сервисами они пользуются. 
Например, использовать 
[OAuth от Github](https://docs.github.com/en/free-pro-team@latest/developers/apps/authorizing-oauth-apps) 
— не самая удачная идея. 
Ваши пользователи не разработчики и вряд ли имеют аккаунт на Github. 
А вот добавить Twitter, Facebook, VK, Google, Yandex или Mail будет хорошей идеей.

Вам не нужно делать фронтенд в этой задаче и реализовывать собственный сервер OAuth. 
Нужно реализовать протокол со стороны потребителя.

Информация по OAuth у разных поставщиков данных: 

- [Twitter](https://developer.twitter.com/en/docs/authentication/overview),
- [Facebook](https://developers.facebook.com/docs/facebook-login/),
- [VK](https://vk.com/dev/access_token),
- [Google](https://developers.google.com/identity/protocols/oauth2),
- [Yandex](https://yandex.ru/dev/oauth/?turbo=true),
- [Mail](https://api.mail.ru/docs/guides/oauth/).

## Дополнительное задание

Реализуйте возможность открепить аккаунт в соцсети от личного кабинета. 

Решение залейте в репозиторий текущего спринта и отправьте на ревью.


# Запуск:
```
make run  # поднимаем контейнеры
```
Документация Swagger размещена по адресу: http://0.0.0.0:5000/swagger/

* Репозиторий с АПИ фильмов (скопировал командный):
[тык](https://github.com/TheZavitaev/Async_API_sprint_2)

* Реализация бэкенда аутентификации:
[тык](https://github.com/TheZavitaev/Async_API_sprint_2/blob/main/backend_api/main.py#L24)

