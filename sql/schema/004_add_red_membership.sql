-- +goose Up
alter table users
add is_chirpy_red boolean default false not null;


-- +goose Down
alter table users
drop is_chirpy_red;



