// Offset for Site Navigation
$('#siteNav').affix({
    offset: {
        top: 100
    }
})

function loadfile(hash){

    $.get( "/api/file/" + hash, function( data ) {
        var filesize = Math.round(data["filesize"]/1024);
        var infos = "<h3>" + data["filename"] + " <small>(" + filesize + " kb)"+ "</small> <a href='/api/file/" + htmlEntities(data['hash']) + "/?raw' class='btn btn-primary btn-xs'>download</a></h3>";
        infos += "<p>" + data["type"] + "</p>";
        var is_image = /\.(gif|png|jpg|jpeg|bmp)$/ig.test(data["filename"]);
        if (is_image){
            infos += "<img src='/api/file/"+data["hash"]+"?raw' />";
        }

        // If is ELF
        if (data["graph"] != undefined) {
            if (data["graph"] == ""){
                infos += "<div id='gen_graph'><h4>Graph</h4><a href='#' onclick='create_graph(\"" + hash + "\");return false;' class='btn btn-primary btn-xs'>Create Graph</a></div>";
            }

            if (data["graph"] != undefined && data["graph"] != false && data["graph"] != ""){
                infos += "<div id='gen_graph'><h4>Graph</h4><img src='/api/file/"+data["hash"]+"?graph'></div>";
            } else if (data["graph"] != undefined && data["graph"] == false && data["graph"] != "") {
                infos += "<div id='gen_graph'><h4>Graph</h4>Graph generation failed.</div>";
            }

        }

        // Informations
        if (data["informations"] != undefined) {
            infos += "<h4>Informations</h4><pre>" + htmlEntities(data["informations"]) + "</pre>";
        }

        //Content
        if (data["content"] != undefined) {
            infos += "<h4>Content</h4><pre>" + htmlEntities(data["content"]) + "</pre>";
        }

        // Loots
        if (data["loots"] != undefined && data["loots"].length > 0) {
            infos += "<h4>Loots</h4>";
            infos += "<pre>";
            for(i=0; i < data["loots"].length; i++) {
                infos += data["loots"][i]["type"] + ": " + data["loots"][i]["info"] + "\n";
            }
            infos += "</pre>";
        }

        // Imports
        if (data["imports"] != undefined) {
            infos += "<h4>Imports</h4><pre>" + htmlEntities(data["imports"]) + "</pre>";
        }

        $("#file_infos").html(infos);
    });
    scrollToAnchor('content');
}

function scrollToAnchor(aid){
    var aTag = $("a[id='"+ aid +"']");
    $('html,body').animate({scrollTop: aTag.offset().top},'slow');
}

function htmlEntities(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function create_graph(hash){
	$("#gen_graph").html("<img src='/static/images/wait.gif' />");
    $.get( "/api/file/"+hash+"?graph", function( data ) {	
        if (data["graph"] != undefined && data["graph"] != false){
            $("#gen_graph").html("<h4>Graph</h4><img src='/api/file/"+data["hash"]+"?graph'>");
        } else if (data["graph"] != undefined && data["graph"] == false) {
            $("#gen_graph").html("<h4>Graph</h4>Graph generation failed.");
        }

    });
}

var waitingDialog = waitingDialog || (function ($) {
    'use strict';

    // Creating modal dialog's DOM
    var $dialog = $(
        '<div class="modal fade" data-backdrop="static" data-keyboard="false" tabindex="-1" role="dialog" aria-hidden="true" style="padding-top:15%; overflow-y:visible;">' +
        '<div class="modal-dialog modal-m">' +
        '<div class="modal-content">' +
            '<div class="modal-header"><h3 style="margin:0;"></h3></div>' +
            '<div class="modal-body">' +
                '<div class="progress progress-striped active" style="margin-bottom:0;"><div class="progress-bar" style="width: 100%"></div></div>' +
            '</div>' +
        '</div></div></div>');

    return {
        /**
         * Opens our dialog
         * @param message Custom message
         * @param options Custom options:
         *                   options.dialogSize - bootstrap postfix for dialog size, e.g. "sm", "m";
         *                   options.progressType - bootstrap postfix for progress bar type, e.g. "success", "warning".
         */
        show: function (message, options) {
            // Assigning defaults
            if (typeof options === 'undefined') {
                options = {};
            }
            if (typeof message === 'undefined') {
                message = 'Loading';
            }
            var settings = $.extend({
                dialogSize: 'm',
                progressType: '',
                onHide: null // This callback runs after the dialog was hidden
            }, options);

            // Configuring dialog
            $dialog.find('.modal-dialog').attr('class', 'modal-dialog').addClass('modal-' + settings.dialogSize);
            $dialog.find('.progress-bar').attr('class', 'progress-bar');
            if (settings.progressType) {
                $dialog.find('.progress-bar').addClass('progress-bar-' + settings.progressType);
            }
            $dialog.find('h3').text(message);
            // Adding callbacks
            if (typeof settings.onHide === 'function') {
                $dialog.off('hidden.bs.modal').on('hidden.bs.modal', function (e) {
                    settings.onHide.call($dialog);
                });
            }
            // Opening dialog
            $dialog.modal();
        },
        /**
         * Closes dialog
         */
        hide: function () {
            $dialog.modal('hide');
        }
    };

})(jQuery);