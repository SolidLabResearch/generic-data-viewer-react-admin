
describe("Templated query", () => {

  // Test to check if the query filters correctly 
  // and test that we can navigate through pages in the result table without having to fill in the query again
  it("With 1 variable", () => {

    cy.visit("/");
    cy.contains("Templated query about my favourite musicians").click();

    // Fill in the query, select Baroque (7 existant artists -> perfect for this test)
    cy.get('form').within(() => {
      cy.get('#genre').click();
    });
    cy.get('li').contains('Baroque').click();

    // Comfirm query
    cy.get('button').contains('Query').click();

    // Check that the page loaded and that we can see the correct data
    cy.contains("Finished in:");
    cy.get('.column-name').find('span').contains("Johann Sebastian Bach");
    cy.get('.column-name').find('span').contains("Marc-Antoine Charpentier");
    // Check that we don't see artists that don't belong here
    cy.get('.column-name').find('span').contains("Franz Schubert").should("not.exist");
    cy.get('.column-name').find('span').contains("Wolfgang Amadeus Mozart").should("not.exist");

    // Set the Rows per page to 5 so that we can go to the next page
    cy.get('.MuiInputBase-root').click();
    cy.get('li').contains('5').click();
    
    // Navigate to page 2, and see if it contains the 6th artist
    cy.get('button').contains('2').click();
    cy.get('.column-name').find('span').contains("Antonio Caldara");

    // To be sure that the form is not appearing we test that the form submit button doesn't exist
    cy.get('form').should("not.exist");
          // cy.get('button').contains('Query').should("not.exist");  -> useless if we add a 'new query' button
  });

  it("With 2 variables", () => {
    cy.visit("/");

    cy.contains("Templated query #2 about my favourite musicians").click();

    cy.get('form').within(() => {
      cy.get('#genre').click();
    });
    cy.get('li').contains('Classical').click();
    cy.get('form').within(() => {
      cy.get('#sameAsUrl').click();
    });
    cy.get('li').contains('Mozart').click();

    cy.get('button').contains('Query').click();
    cy.contains("Finished in:");
    cy.get('.column-name').find('span').contains("Wolfgang Amadeus Mozart");
  });
});
