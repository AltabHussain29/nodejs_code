const englishCode = "en-US";
const spanishCode = "es-ES";

function getLanguageLink(language) {
    switch (language.toLowerCase()) {
        case englishCode.toLowerCase():
            return "/about-us";
        case spanishCode.toLowerCase():
            return "/acerca-de";
    }
    return '';
}

module.exports = getLanguageLink;