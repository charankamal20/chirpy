-- +goose Up
create table chirps (
    id varchar(256) not null primary key,
    user_id varchar(256) not null,
    body text not null,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now(),
    foreign key (user_id) references users(id) on delete cascade
);


-- +goose Down
drop table chirps;
