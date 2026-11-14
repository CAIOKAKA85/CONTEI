-- CONTEI · Esquema de banco de dados (PostgreSQL / Supabase)
-- Pensado para a LGPD: minimização, controle de acesso por linha (RLS),
-- registro de consentimento, trilha de auditoria e eliminação sob pedido do titular.
-- Revise com um advogado e com quem for operar o banco antes de ir para produção.
--
-- BOAS PRÁTICAS QUE VÃO ALÉM DO SQL (configurar no provedor):
--  * Senhas: NUNCA guardar no seu banco. Use o serviço de autenticação (Supabase Auth,
--    Firebase Auth, Auth0), que usa hash forte (bcrypt/argon2), login Google/Apple e
--    redefinição de senha por código/link enviado ao e-mail.
--  * Criptografia em repouso e em trânsito (TLS) ativas; backups criptografados.
--  * Autenticação em dois fatores obrigatória para administradores e funcionários.
--  * Princípio do menor privilégio: a chave de serviço (service_role) nunca vai para o navegador.
--  * Região do servidor preferencialmente no Brasil; contrato (DPA) com cada operador.
--  * Documentos de clientes em bucket PRIVADO, com links assinados de curta duração.
--  * Nomear o encarregado (DPO), publicar a Política de Privacidade e manter o
--    registro das operações de tratamento (ROPA).

create extension if not exists pgcrypto;

create type papel   as enum ('cliente','admin','funcionario');
create type plano   as enum ('essencial','profissional','premium');
create type situacao as enum ('pendente','ativo','pausado');

-- Perfil (1 por usuário do Auth). Só o necessário para o serviço.
create table perfis (
  id               uuid primary key references auth.users(id) on delete cascade,
  nome             text not null,
  email            text not null unique,
  telefone         text,
  papel            papel not null default 'cliente',
  plano            plano,
  situacao         situacao not null default 'pendente',
  pago_ate         date,                          -- mensalidade (renovação manual ou recorrente)
  aceite_politica_em timestamptz,                 -- consentimento (LGPD art. 8º)
  versao_politica  text,
  criado_em        timestamptz not null default now(),
  atualizado_em    timestamptz not null default now()
);

create table contas_pagar (
  id          uuid primary key default gen_random_uuid(),
  cliente_id  uuid not null references perfis(id) on delete cascade,
  descricao   text not null,
  valor       numeric(12,2) not null check (valor > 0),
  vencimento  date not null,
  recorrente  boolean not null default false,
  paga        boolean not null default false,
  criado_em   timestamptz not null default now()
);

create table minutas (                            -- gerenciadas pela extranet admin
  id         uuid primary key default gen_random_uuid(),
  titulo     text not null,
  categoria  text not null default 'Geral',
  descricao  text,
  texto      text not null,
  publicada  boolean not null default true,
  atualizado_em timestamptz not null default now()
);

create table mensagens (
  id          uuid primary key default gen_random_uuid(),
  cliente_id  uuid not null references perfis(id) on delete cascade,
  origem      text not null check (origem in ('cliente','equipe')),
  destino     text,
  texto       text not null,
  criado_em   timestamptz not null default now()
);

create table reunioes_solicitadas (
  id          uuid primary key default gen_random_uuid(),
  cliente_id  uuid not null references perfis(id) on delete cascade,
  assunto     text not null,
  preferencia timestamptz,
  atendida    boolean not null default false,
  criado_em   timestamptz not null default now()
);

create table reunioes (                           -- marcadas pelos profissionais
  id          uuid primary key default gen_random_uuid(),
  cliente_id  uuid not null references perfis(id) on delete cascade,
  plataforma  text not null check (plataforma in ('Google Meet','Zoom','Outra')),
  link        text not null check (link like 'https://%'),
  inicio      timestamptz not null,
  assunto     text,
  criado_por  uuid references perfis(id)
);

-- Pedidos do titular (LGPD art. 18): acesso, correção, eliminação, portabilidade...
create table solicitacoes_titular (
  id          uuid primary key default gen_random_uuid(),
  cliente_id  uuid references perfis(id) on delete set null,
  tipo        text not null check (tipo in ('acesso','correcao','eliminacao','portabilidade','revogacao')),
  status      text not null default 'aberta',
  criado_em   timestamptz not null default now(),
  concluido_em timestamptz
);

-- Trilha de auditoria: quem fez o quê e quando (sem guardar o conteúdo sensível).
create table auditoria (
  id        bigint generated always as identity primary key,
  quando    timestamptz not null default now(),
  autor_id  uuid,
  acao      text not null,        -- ex.: 'cliente.pausado', 'mensalidade.renovada'
  alvo      text
);

-- ---------- Segurança por linha (RLS) ----------
alter table perfis               enable row level security;
alter table contas_pagar         enable row level security;
alter table minutas              enable row level security;
alter table mensagens            enable row level security;
alter table reunioes_solicitadas enable row level security;
alter table reunioes             enable row level security;
alter table solicitacoes_titular enable row level security;
alter table auditoria            enable row level security;

create function eh_equipe() returns boolean language sql stable security definer as $$
  select exists (select 1 from perfis where id = auth.uid() and papel in ('admin','funcionario'));
$$;

-- Cliente enxerga e altera só o que é dele; equipe gerencia tudo.
create policy perfis_ler    on perfis for select using (id = auth.uid() or eh_equipe());
create policy perfis_equipe on perfis for all    using (eh_equipe()) with check (eh_equipe());

create policy contas_dono   on contas_pagar for all using (cliente_id = auth.uid()) with check (cliente_id = auth.uid());
create policy contas_equipe on contas_pagar for select using (eh_equipe());

create policy minutas_ler    on minutas for select using (publicada or eh_equipe());
create policy minutas_equipe on minutas for all    using (eh_equipe()) with check (eh_equipe());

create policy msg_dono   on mensagens for select using (cliente_id = auth.uid() or eh_equipe());
create policy msg_enviar on mensagens for insert with check (
  (cliente_id = auth.uid() and origem = 'cliente') or (eh_equipe() and origem = 'equipe'));

create policy sol_dono   on reunioes_solicitadas for all using (cliente_id = auth.uid() or eh_equipe())
  with check (cliente_id = auth.uid() or eh_equipe());
create policy reu_ler    on reunioes for select using (cliente_id = auth.uid() or eh_equipe());
create policy reu_equipe on reunioes for all using (eh_equipe()) with check (eh_equipe());   -- cliente NÃO cria/edita

create policy titular_dono   on solicitacoes_titular for all using (cliente_id = auth.uid() or eh_equipe())
  with check (cliente_id = auth.uid() or eh_equipe());
create policy auditoria_equipe on auditoria for select using (eh_equipe());

-- Acesso conforme o plano e a mensalidade (usar no app e em consultas protegidas).
create function acesso_liberado(uid uuid) returns boolean language sql stable security definer as $$
  select exists (select 1 from perfis
    where id = uid and (papel <> 'cliente' or (situacao = 'ativo' and plano is not null and pago_ate >= current_date)));
$$;
create function reunioes_liberadas(uid uuid) returns boolean language sql stable security definer as $$
  select exists (select 1 from perfis where id = uid and plano = 'premium' and situacao = 'ativo' and pago_ate >= current_date);
$$;

-- Eliminação de conta: apagar o usuário no Auth remove perfil e dados ligados (on delete cascade).
-- Guarde apenas o que a lei exigir (ex.: registros fiscais/cobrança) por prazo definido, de forma isolada.
