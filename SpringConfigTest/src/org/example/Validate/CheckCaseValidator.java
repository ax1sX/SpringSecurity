package org.example.Validate;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class CheckCaseValidator implements ConstraintValidator<CheckCase,String> {

    private CaseMode caseMode;

    @Override
    public void initialize(CheckCase constraintAnnotation) {
        this.caseMode=constraintAnnotation.value();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if ( value == null ) {
            return true;
        }

        boolean isValid;
        String message = value;
        if ( caseMode == CaseMode.LOWER ) {
            isValid = value.equals( value.toLowerCase() );
            message = message + " should be in lower case.";
        }
        else {
            isValid = value.equals( value.toUpperCase() );
            message = message + " should be in upper case.";
        }

        if ( !isValid ) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(message)
                    .addConstraintViolation();
        }
        return false;
    }
}
