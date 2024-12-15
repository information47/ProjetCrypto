document.addEventListener("DOMContentLoaded", () => {
  const mdp_input = document.getElementById("password");
  const mdp_indicateur = document.getElementById("mdp_indicateur");
  const msg = document.getElementById("msg");

  const evaluatePasswordStrength = (password) => {
    let score = 0;

    const minumLength = password.length >= 8;
    const upperCase = /[A-Z]/.test(password);
    const lowerCase = /[a-z]/.test(password);
    const number = /[0-9]/.test(password);
    const specialChar = /[^A-Za-z0-9]/.test(password);

    if (minumLength) {
      score++;
      if (upperCase) score++;
      if (lowerCase) score++;
      if (number) score++;
      if (specialChar) score++;
    }

    if (score >= 4 && !specialChar) {
      score = 3;
    }

    return score;
  };

  const updatemdp_indicateur = (score) => {
    const levels = [
      { color: "red", message: "Très faible" },
      { color: "orange", message: "Faible" },
      { color: "yellow", message: "Moyen" },
      { color: "blue", message: "Bon" },
      { color: "green", message: "Fort" },
    ];

    const level = levels[Math.min(score, levels.length - 1)];

    const widthPercentage = Math.max((score / 5) * 100, 10);

    mdp_indicateur.style.width = `${widthPercentage}%`;
    mdp_indicateur.style.backgroundColor = level.color;

    msg.textContent = level.message;
  };

  mdp_input.addEventListener("input", () => {
    const password = mdp_input.value;
    const score = evaluatePasswordStrength(password);

    updatemdp_indicateur(score);
  });
});
