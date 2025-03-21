
describe("Templated query", () => {

  // Test to check if the query filters correctly 
  // and test that we can navigate through pages in the result table without having to fill in the query again
  it("With 1 variable", () => {

    cy.visit("/");
    cy.contains("Example queries").click();
    cy.contains("A templated query about musicians").click();

    // Fill in the query, select Baroque (7 existing artists -> perfect for this test)
    cy.get('form').within(() => {
      cy.get('#genre').click();
    });
    cy.get('li').contains('Baroque').click();

    // Comfirm query
    cy.get('button').contains('Query').click();

    // Check the display of the variable(s) and their value
    cy.contains("genre: \"Baroque\"");

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

  it("With 1 variables, double expansion", () => {
    cy.visit("/");
    cy.contains("For testing only").click();
    cy.contains("A templated query about musicians (double results)").click();

    cy.get('form').within(() => {
      cy.get('#genre').click();
    });
    cy.get('li').contains('Romantic').click();

    cy.get('button').contains('Query').click();
    cy.contains("Finished in:");
    cy.get('.column-name').find('span').should("have.length", 2);
  });

  it("With 2 variables; change variables", () => {
    cy.visit("/");
    cy.contains("Example queries").click();
    cy.contains("A templated query about musicians (two variables)").click();

    cy.get('form').within(() => {
      cy.get('#genre').click();
    });
    cy.get('li').contains('Classical').click();
    cy.get('form').within(() => {
      cy.get('#sameAsUrl').click();
    });
    cy.get('li').contains('Mozart').click();

    cy.get('button').contains('Query').click();

    // Check the display of the variable(s) and their value
    cy.contains("genre: \"Classical\"");
    cy.contains("sameAsUrl: <https://en.wikipedia.org/wiki/Wolfgang_Amadeus_Mozart>");

    // Check that the page loaded and that we can see the correct data
    cy.contains("Finished in:");
    cy.get('.column-name').find('span').contains("Wolfgang Amadeus Mozart").should("exist");;
    cy.get('.column-name').find('span').contains("Franz Schubert").should("not.exist");
    cy.get('.column-name').find('span').contains("Johann Sebastian Bach").should("not.exist");
    cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should("not.exist");

    // Check if the button to make a new query exists and use it
    cy.get('button').contains("Change Variables").should("exist");
    cy.get('button').contains("Change Variables").click();

    // Making sure we get the form to enter new variables
    // and that the previously selected value(s) are still there
    cy.get('form').within(() => {
      cy.get('#genre').should('have.value', '"Classical"');
      cy.get('#sameAsUrl').should('have.value', '<https://en.wikipedia.org/wiki/Wolfgang_Amadeus_Mozart>');
    });

    // Previously selected variables are still there; submit the same combination again
    cy.get('button[type="submit"]').click();

    cy.contains("Finished in:");
    cy.get('.column-name').find('span').contains("Wolfgang Amadeus Mozart").should("exist");;
    cy.get('.column-name').find('span').contains("Franz Schubert").should("not.exist");
    cy.get('.column-name').find('span').contains("Johann Sebastian Bach").should("not.exist");
    cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should("not.exist");

    // Change variables and make a nonexisting combination
    cy.get('button').contains("Change Variables").should("exist");
    cy.get('button').contains("Change Variables").click();

    cy.get('form').within(() => {
      cy.get('#genre').click();
    });
    cy.get('li').contains('Baroque').click();

    cy.get('form').within(() => {
      cy.get('#sameAsUrl').click();
    });
    cy.get('li').contains('Beethoven').click();

    cy.get('button[type="submit"]').click();

    cy.get('span').contains("The result list is empty.").should("exist");

    // Change variables and make another existing combination
    cy.get('button').contains("Change Variables").should("exist");
    cy.get('button').contains("Change Variables").click();

    cy.get('form').within(() => {
      cy.get('#genre').click();
    });
    cy.get('li').contains('Romantic').click();

    cy.get('form').within(() => {
      cy.get('#sameAsUrl').click();
    });
    cy.get('li').contains('Schubert').click();

    cy.get('button[type="submit"]').click();

    cy.get('span').contains("The result list is empty.").should("not.exist");
    cy.get('.column-name').find('span').contains("Ludwig van Beethoven").should("not.exist");
    cy.get('.column-name').find('span').contains("Johann Sebastian Bach").should("not.exist");
    cy.get('.column-name').find('span').contains("Antonio Vivaldi").should("not.exist");
    cy.get('.column-name').find('span').contains("Franz Schubert").should("exist");

  });

  it("Correct message displayed when no resulting data", () => {
    cy.visit("/");
    cy.contains("Example queries").click();
    cy.contains("A templated query about musicians (two variables)").click();

    // Chose a genre
    cy.get('form').within(() => {
      cy.get('#genre').click();
    });
    cy.get('li').contains('Classical').click();

     // Pick the wrong url so we force an empty result
    cy.get('form').within(() => {
      cy.get('#sameAsUrl').click();
    });
    cy.get('li').contains('Bach').click();

    // Confirm this query
    cy.get('button').contains('Query').click();

    // Check that we see the correct message
    cy.get('span').contains("The result list is empty.").should("exist");
  });

  it("Able to change variables after having no results", () => {
    cy.visit("/");
    cy.contains("Example queries").click();
    cy.contains("A templated query about musicians (two variables)").click();

    // Chose a genre
    cy.get('form').within(() => {
      cy.get('#genre').click();
    });
    cy.get('li').contains('Classical').click();

     // Pick the wrong url so we force an empty result
    cy.get('form').within(() => {
      cy.get('#sameAsUrl').click();
    });
    cy.get('li').contains('Bach').click();

    // Confirm this query
    cy.get('button').contains('Query').click();

    // Check that we see the correct message
    cy.get('span').contains("The result list is empty.").should("exist");

    cy.get('button').contains("Change Variables").should("exist");
    cy.get('button').contains("Change Variables").click();

    // Making sure we get the form to enter new variables
    // and that the previously selected value(s) are still there
    cy.get('form').within(() => {
      cy.get('#genre').should("exist");
      cy.get('#genre').should('have.value', '"Classical"');
      cy.get('#sameAsUrl').should('have.value', '<https://en.wikipedia.org/wiki/Johann_Sebastian_Bach>');
    });

  });

});
