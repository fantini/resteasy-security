package br.com.fantini.resteasy.security.provider.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import br.com.fantini.resteasy.security.utils.TypeLog;

@Target(value = { ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface RestLog {
	TypeLog[] value();
	boolean transaction() default false;
}
