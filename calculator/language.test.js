const getLanguageLink = require("./language.js")

describe("Language parse Test", () => {
    test("Returns about-us for english language", () => {
        expect(getLanguageLink("en-US")).toBe("/about-us");
    });
    
    test("Returns acerca-de for spanish language", () => {
        expect(getLanguageLink("es-ES")).toBe("/acerca-de");
    });
    
    test("Returns Empty for other language", () => {
        expect(getLanguageLink("hi-IN")).toBe("");
    });
});
