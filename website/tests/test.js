const { sum, subtract, multiply } = require("./server")

describe("Calculate functions Test", () => {
    test('Addition of two numbers', () => {
        expect(sum(1, 2)).toBe(3)
    });
    
    test('Subtraction of two numbers', () => {
        expect(subtract(4, 1)).toBe(3)
    });
    
    test('Multiplication of two numbers', () =>{
        expect(multiply(1, 3)).toBe(3)
    });
});
