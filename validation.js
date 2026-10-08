import validator from 'validator';

export const validateEmail = (email) => {
  return validator.isEmail(email);
};

export const validatePassword = (password) => {
  if (password.length < 6) return 'Password must be at least 6 characters';
  if (!/[A-Z]/.test(password)) return 'Password must contain uppercase letters';
  if (!/[0-9]/.test(password)) return 'Password must contain numbers';
  return null;
};

export const validateUsername = (username) => {
  if (username.length < 3) return 'Username must be at least 3 characters';
  if (!/^[a-zA-Z0-9._]+$/.test(username)) {
    return 'Username can only contain letters, numbers, dots, and underscores';
  }
  return null;
};

export const sanitizeInput = (input) => {
  return validator.trim(validator.escape(input));
};
