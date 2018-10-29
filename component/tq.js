'use strict';

polarity.export = PolarityComponent.extend({
    actions: {
        addComment: function (id, comment) {
            let self = this;
            self.set('message', `Adding...`);

            this.sendIntegrationMessage({ data: { id: id, comment: comment } })
                .then(function (/* response */) {
                    self.set('message', "Success!");
                }).catch(function (err) {
                    console.error(err);
                    self.set('message', "Error adding comment");
                });
        },
        onSelectPlaybook: function (value) {
            playbookId = value;
        }
    },
});

