package io.insource.springboot.security.condition;

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.lang.annotation.Annotation;
import java.util.Arrays;

public class EnableAnnotationCondition<T extends Annotation> extends SpringBootCondition {
    private final Class<T> annotationClass;
    private final String annotationName;

    public EnableAnnotationCondition(Class<T> annotationClass) {
        this.annotationClass = annotationClass;
        this.annotationName = annotationClass.getSimpleName();
    }

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        String[] enablers = context.getBeanFactory().getBeanNamesForAnnotation(annotationClass);
        ConditionMessage.Builder message = ConditionMessage.forCondition("@" + annotationName + " Condition");

        return enablers.length > 0
            ? ConditionOutcome.match(message.found("@" + annotationName + " annotation").items(Arrays.asList(enablers)))
            : ConditionOutcome.noMatch(message.didNotFind("@" + annotationName + " annotation").atAll());

    }
}
