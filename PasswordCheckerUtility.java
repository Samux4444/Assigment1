import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PasswordCheckerUtility {
    
    // Main method to check if a password is valid based on multiple conditions
    public static boolean isValidPassword(String password) throws LengthException, NoDigitException, NoUpperAlphaException, NoLowerAlphaException, InvalidSequenceException, NoSpecialCharacterException, WeakPasswordException {
        // Validate the length of the password
        isValidLength(password);
        
        // Check if the password contains a digit
        hasDigit(password);
        
        // Check if the password contains an uppercase character
        hasUpperAlpha(password);
        
        // Check if the password contains a lowercase character
        hasLowerAlpha(password);
        
        // Check if the password contains a special character
        hasSpecialChar(password);

        // Check if the password has any invalid sequences (e.g., "aaa", "111")
        hasInvalidSequence(password);

        // Check if the password is considered weak
        isWeakPassword(password);

        // If all checks pass, return true
        return true;
    }

    // Method to check if a password is weak (but not necessarily invalid)
    public static boolean isWeakPassword(String password) throws WeakPasswordException {
        if (password == null) {
            throw new WeakPasswordException("Password cannot be null.");
        }

        int length = password.length();
        if (length >= 6 && length <= 9) {
            throw new WeakPasswordException("Password is weak because its length is between 6 and 9 characters.");
        }

        return false;
    }

    // Method to find invalid passwords from an ArrayList
    public static ArrayList<String> getInvalidPasswords(ArrayList<String> passwords) {
        ArrayList<String> invalidPasswords = new ArrayList<>();
        for (String password : passwords) {
            try {
                isValidPassword(password);
            } catch (Exception e) {
                invalidPasswords.add(password + " " + e.getMessage());
            }
        }
        return invalidPasswords;
    }

    // Method to check if a password has a length of at least 6 characters
    public static void hasBetweenSixAndNineChars(String password) throws LengthException {
        int length = password.length();
        if (length < 6) {
            throw new LengthException("Password length must be at least 6 characters.");
        }
    }

    // Method to check if a password contains at least one digit
    public static void hasDigit(String password) throws NoDigitException {
        boolean digitFound = false;
        for (char c : password.toCharArray()) {
            if (Character.isDigit(c)) {
                digitFound = true;
                break;
            }
        }
        if (!digitFound) {
            throw new NoDigitException("Password must contain at least one digit.");
        }
    }

    // Method to check if a password contains at least one uppercase character
    public static boolean hasUpperAlpha(String password) throws NoUpperAlphaException {
        boolean upperFound = false;
        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                upperFound = true;
                return true;
            }
        }
        if (!upperFound) {
            throw new NoUpperAlphaException("Password must contain at least one uppercase alphabetic character.");
        }
        return false;
    }

    // Method to check if a password contains at least one lowercase character
    public static void hasLowerAlpha(String password) throws NoLowerAlphaException {
        boolean lowerFound = false;
        for (char c : password.toCharArray()) {
            if (Character.isLowerCase(c)) {
                lowerFound = true;
                break;
            }
        }
        if (!lowerFound) {
            throw new NoLowerAlphaException("The password must contain at least one lowercase alphabetic character");
        }
    }

    // Method to check if a password has more than 2 of the same character in sequence
    public static void hasInvalidSequence(String password) throws InvalidSequenceException {
        for (int i = 0; i < password.length() - 2; i++) {
            if (password.charAt(i) == password.charAt(i + 1) && password.charAt(i) == password.charAt(i + 2)) {
                throw new InvalidSequenceException("Password cannot contain more than 2 of the same character in sequence.");
            }
        }
    }

    // Method to compare two passwords for equality
    public static boolean comparePasswordsWithReturn(String password, String passwordConfirm) {
        if (password == null || passwordConfirm == null) {
            return false;
        }
        return password.equals(passwordConfirm);
    }

    // Method to check if a password has at least one special character
    public static void hasSpecialChar(String password) throws NoSpecialCharacterException {
        Pattern pattern = Pattern.compile("[!@#$%^&*()-+]");
        Matcher matcher = pattern.matcher(password);
        if (!matcher.find()) {
            throw new NoSpecialCharacterException("The password must contain at least one special character");
        }
    }

    // Method to compare two passwords and throw an exception if they don't match
    public static void comparePasswords(String password, String passwordConfirm) throws UnmatchedException {
        if (password == null || passwordConfirm == null) {
            throw new UnmatchedException("One or both of the passwords are null.");
        }

        if (!password.equals(passwordConfirm)) {
            throw new UnmatchedException("Passwords do not match");
        }
    }

    // Method to check if a password has a valid length (at least 6 characters)
    public static boolean isValidLength(String password) throws LengthException {
        if (password == null) {
            throw new LengthException("Password cannot be null.");
        }

        if (password.length() < 6) {
            throw new LengthException("The password must be at least 6 characters long");
        }

        return true;
    }
}
