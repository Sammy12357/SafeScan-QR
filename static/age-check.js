(() => {
  const yearInput = document.getElementById("birthYear");
  const birthdayQuestion = document.querySelector(".age-birthday-choice");
  if (!yearInput || !birthdayQuestion) return;

  const radios = Array.from(birthdayQuestion.querySelectorAll('input[name="birthday_this_year"]'));
  const minimumAge = Number(birthdayQuestion.dataset.minimumAge);
  const currentYear = Number(birthdayQuestion.dataset.currentYear);
  if (!Number.isInteger(minimumAge) || !Number.isInteger(currentYear) || !radios.length) return;

  function updateBirthdayQuestion() {
    const yearText = yearInput.value.trim();
    const needsAnswer = /^[0-9]{4}$/.test(yearText) &&
      Number(yearText) === currentYear - minimumAge;
    birthdayQuestion.hidden = !needsAnswer;
    radios.forEach((radio) => {
      radio.disabled = !needsAnswer;
      radio.required = needsAnswer && radio.value === "yes";
      if (!needsAnswer) radio.checked = false;
    });
  }

  yearInput.addEventListener("input", updateBirthdayQuestion);
  yearInput.addEventListener("change", updateBirthdayQuestion);
  window.addEventListener("pageshow", updateBirthdayQuestion);
  updateBirthdayQuestion();
})();
