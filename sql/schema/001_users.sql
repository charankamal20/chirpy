-- +goose Up
create table users (
    id varchar(256) primary key,
    email TEXT not null unique,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now()
);


-- +goose Down
drop table users;
