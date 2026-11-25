(function (root) {
    'use strict';

    var existing = root.MauticAuthAlternativeCoordinator;
    if (existing) {
        if (typeof existing.install === 'function') {
            existing.install();
        }
        if (typeof existing.coordinate === 'function') {
            existing.coordinate();
        } else if (typeof existing.sync === 'function') {
            existing.sync();
        } else if (typeof existing.run === 'function') {
            existing.run();
        }

        return;
    }

    var blockSelector      = '[data-mautic-auth-alternative-block="1"]';
    var separatorSelector  = '[data-mautic-auth-alternative-separator="1"]';
    var observerInstalled  = false;
    var observer           = null;
    var coordinationQueued = false;
    var readyListenerAdded = false;

    var getDocument = function () {
        return root.document;
    };

    var findBlocks = function () {
        var document = getDocument();

        return document ? Array.prototype.slice.call(document.querySelectorAll(blockSelector)) : [];
    };

    var findSeparators = function () {
        var document = getDocument();

        return document ? Array.prototype.slice.call(document.querySelectorAll(separatorSelector)) : [];
    };

    var removeNode = function (node) {
        if (node && node.parentNode) {
            node.parentNode.removeChild(node);
        }
    };

    var schedule = function () {
        if (coordinationQueued) {
            return;
        }

        coordinationQueued = true;
        var run = function () {
            coordinationQueued = false;
            coordinate();
        };

        if (typeof root.queueMicrotask === 'function') {
            root.queueMicrotask(run);
        } else if (typeof root.setTimeout === 'function') {
            root.setTimeout(run, 0);
        } else {
            run();
        }
    };

    var coordinate = function () {
        var blocks      = findBlocks();
        var separators  = findSeparators();
        var topBlock    = blocks[0];
        var separator;
        var label;

        if (!topBlock) {
            separators.forEach(removeNode);

            return;
        }

        label = topBlock.getAttribute('data-mautic-auth-separator-label') || '';
        if ('' === label) {
            separators.forEach(removeNode);

            return;
        }

        separator = separators[0];
        if (!separator) {
            separator = getDocument().createElement('div');
        }

        separator.setAttribute('class', 'mautic-auth-alternative-separator');
        separator.setAttribute('data-mautic-auth-alternative-separator', '1');
        if (separator.textContent !== label) {
            separator.textContent = label;
        }

        separators.forEach(function (candidate) {
            if (candidate !== separator) {
                removeNode(candidate);
            }
        });

        if (topBlock.parentNode && (separator.parentNode !== topBlock.parentNode || separator.nextSibling !== topBlock)) {
            topBlock.parentNode.insertBefore(separator, topBlock);
        }
    };

    var install = function () {
        var document = getDocument();
        if (!document) {
            return;
        }

        if (!document.body) {
            if (!readyListenerAdded && typeof document.addEventListener === 'function') {
                readyListenerAdded = true;
                document.addEventListener('DOMContentLoaded', function () {
                    install();
                    coordinate();
                });
            }

            return;
        }

        if (observerInstalled || typeof root.MutationObserver !== 'function') {
            return;
        }

        observer = new root.MutationObserver(schedule);
        observer.observe(document.body, { childList: true, subtree: true });
        observerInstalled = true;
    };

    root.MauticAuthAlternativeCoordinator = {
        coordinate: coordinate,
        install: install,
        run: coordinate,
        sync: schedule,
        register: function () {
            install();
            coordinate();
        },
    };

    install();
    coordinate();
}(window));
