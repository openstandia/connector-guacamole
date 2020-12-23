package jp.openstandia.connector.guacamole;


@FunctionalInterface
public interface GuacamoleQueryHandler<T> {
    boolean handle(T arg);
}